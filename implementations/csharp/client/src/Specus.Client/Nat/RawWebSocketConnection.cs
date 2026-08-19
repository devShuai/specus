using System.Buffers;
using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Specus.Client.Nat;

/// <summary>
/// Minimal RFC 6455 client transport used by WebSocket Specus. Unlike ClientWebSocket it exposes
/// physical frames, including continuation boundaries, FIN/RSV and ping/pong, so SWS2 can carry
/// them without semantic loss.
/// </summary>
internal sealed class RawWebSocketConnection : IAsyncDisposable
{
    private const int MaximumHandshakeBytes = 64 * 1024;
    private const int MaximumFrameBytes = 16 * 1024 * 1024;
    private const string WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private readonly TcpClient? _tcp;
    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private int _aborted;
    private int _disposeState;
    private bool _closeSent;
    private readonly FragmentValidationState _readState = new();
    private readonly FragmentValidationState _writeState = new();

    private RawWebSocketConnection(TcpClient tcp, Stream stream)
    {
        _tcp = tcp;
        _stream = stream;
    }

    private RawWebSocketConnection(Stream stream)
    {
        _stream = stream;
    }

    internal static RawWebSocketConnection CreateForTesting(Stream stream) => new(stream);

    public bool IsOpen => Volatile.Read(ref _aborted) == 0;

    public static async Task<RawWebSocketConnection> ConnectAsync(Uri target,
        IReadOnlyList<KeyValuePair<string, string>> headers,
        CancellationToken cancellationToken)
    {
        if (!target.IsAbsoluteUri || target.Scheme is not ("ws" or "wss"))
        {
            throw new ArgumentException("WebSocket target must use ws or wss", nameof(target));
        }

        var port = target.IsDefaultPort
            ? target.Scheme == "wss" ? 443 : 80
            : target.Port;
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            await tcp.ConnectAsync(target.Host, port, cancellationToken).ConfigureAwait(false);
            Stream stream = tcp.GetStream();
            if (target.Scheme == "wss")
            {
                // Verified like any other upstream connection, and through the same policy as the
                // HTTP path, so a target configured once behaves the same on either protocol.
                var options = UpstreamTlsPolicy.Current.CreateOptions(target.IdnHost);
                var tls = new SslStream(stream, leaveInnerStreamOpen: false,
                    options.RemoteCertificateValidationCallback is null
                        ? null
                        : new RemoteCertificateValidationCallback(options.RemoteCertificateValidationCallback));
                await tls.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(false);
                stream = tls;
            }

            var keyBytes = new byte[16];
            RandomNumberGenerator.Fill(keyBytes);
            var key = Convert.ToBase64String(keyBytes);
            var requestTarget = target.GetComponents(UriComponents.PathAndQuery, UriFormat.UriEscaped);
            if (string.IsNullOrEmpty(requestTarget))
            {
                requestTarget = "/";
            }
            else if (requestTarget[0] != '/')
            {
                requestTarget = "/" + requestTarget;
            }

            var request = new StringBuilder();
            request.Append("GET ").Append(requestTarget).Append(" HTTP/1.1\r\n")
                .Append("Host: ").Append(target.Authority).Append("\r\n")
                .Append("Upgrade: websocket\r\n")
                .Append("Connection: Upgrade\r\n")
                .Append("Sec-WebSocket-Key: ").Append(key).Append("\r\n")
                .Append("Sec-WebSocket-Version: 13\r\n");
            foreach (var header in headers)
            {
                if (!IsSafeHeader(header.Key, header.Value))
                {
                    continue;
                }
                request.Append(header.Key).Append(": ").Append(header.Value.Trim()).Append("\r\n");
            }
            request.Append("\r\n");
            await stream.WriteAsync(Encoding.UTF8.GetBytes(request.ToString()), cancellationToken)
                .ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var responseHeader = await ReadHttpHeaderAsync(stream, cancellationToken).ConfigureAwait(false);
            ValidateHandshakeResponse(responseHeader, key);
            return new RawWebSocketConnection(tcp, stream);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    public async ValueTask<RawWebSocketFrame?> ReadFrameAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var header = new byte[2];
        if (!await TryReadExactlyAsync(_stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var finalFragment = (header[0] & 0x80) != 0;
        var rsv = (byte)((header[0] >> 4) & 0x07);
        var opcode = (byte)(header[0] & 0x0f);
        var masked = (header[1] & 0x80) != 0;
        if (masked)
        {
            throw new InvalidDataException("server WebSocket frame must not be masked");
        }

        ulong length = (uint)(header[1] & 0x7f);
        if (length == 126)
        {
            var extended = new byte[2];
            await ReadExactlyAsync(_stream, extended, cancellationToken).ConfigureAwait(false);
            length = BinaryPrimitives.ReadUInt16BigEndian(extended);
            if (length < 126)
            {
                throw new InvalidDataException("non-minimal WebSocket frame length");
            }
        }
        else if (length == 127)
        {
            var extended = new byte[8];
            await ReadExactlyAsync(_stream, extended, cancellationToken).ConfigureAwait(false);
            length = BinaryPrimitives.ReadUInt64BigEndian(extended);
            if ((length & (1UL << 63)) != 0 || length <= ushort.MaxValue)
            {
                throw new InvalidDataException("invalid WebSocket frame length");
            }
        }
        if (length > MaximumFrameBytes)
        {
            throw new InvalidDataException("WebSocket frame exceeds limit");
        }

        ValidateFrameHeader(opcode, finalFragment, rsv, length);
        var payload = new byte[(int)length];
        await ReadExactlyAsync(_stream, payload, cancellationToken).ConfigureAwait(false);
        var frame = new RawWebSocketFrame(opcode, finalFragment, rsv, payload);
        ValidateFramePayload(frame);
        ValidateFragmentSequence(frame, _readState);
        return frame;
    }

    public async ValueTask WriteFrameAsync(RawWebSocketFrame frame, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ValidateFrameHeader(frame.Opcode, frame.FinalFragment, frame.Rsv, (ulong)frame.Payload.Length);
        if (frame.Payload.Length > MaximumFrameBytes)
        {
            throw new InvalidDataException("WebSocket frame exceeds limit");
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            ValidateFramePayload(frame);
            ValidateFragmentSequence(frame, _writeState);
            await WriteFrameLockedAsync(frame, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async ValueTask ReplyToCloseAsync(RawWebSocketFrame frame, CancellationToken cancellationToken)
    {
        if (frame.Opcode != Specus.Protocol.WebSocketSpecusFrame.OpcodeClose || !IsOpen)
        {
            return;
        }
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!_closeSent)
            {
                await WriteFrameLockedAsync(frame, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public void Abort()
    {
        if (Interlocked.Exchange(ref _aborted, 1) != 0)
        {
            return;
        }
        try { _tcp?.Client.Shutdown(SocketShutdown.Both); }
        catch { /* already closed */ }
        _tcp?.Dispose();
        if (_tcp is null)
        {
            _stream.Dispose();
        }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeState, 1) != 0)
        {
            return ValueTask.CompletedTask;
        }
        Abort();
        _writeLock.Dispose();
        return ValueTask.CompletedTask;
    }

    private static async Task<string> ReadHttpHeaderAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = new List<byte>(1024);
        var one = new byte[1];
        while (bytes.Count < MaximumHandshakeBytes)
        {
            var read = await stream.ReadAsync(one, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("WebSocket handshake response ended early");
            }
            bytes.Add(one[0]);
            if (bytes.Count >= 4
                && bytes[^4] == '\r' && bytes[^3] == '\n'
                && bytes[^2] == '\r' && bytes[^1] == '\n')
            {
                return Encoding.ASCII.GetString(bytes.ToArray());
            }
        }
        throw new InvalidDataException("WebSocket handshake headers exceed limit");
    }

    private static void ValidateHandshakeResponse(string response, string key)
    {
        var lines = response.Split("\r\n", StringSplitOptions.None);
        var status = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (status.Length < 2 || !status[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)
            || status[1] != "101")
        {
            throw new InvalidDataException($"WebSocket handshake failed: {lines[0]}");
        }

        var headers = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            if (line.Length == 0)
            {
                break;
            }
            var separator = line.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0)
            {
                throw new InvalidDataException("malformed WebSocket handshake header");
            }
            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (!headers.TryGetValue(name, out var values))
            {
                values = [];
                headers[name] = values;
            }
            values.Add(value);
        }

        if (!HeaderHasToken(headers, "Upgrade", "websocket")
            || !HeaderHasToken(headers, "Connection", "upgrade"))
        {
            throw new InvalidDataException("WebSocket handshake missing upgrade headers");
        }
        var expected = Convert.ToBase64String(
            SHA1.HashData(Encoding.ASCII.GetBytes(key + WebSocketGuid)));
        if (!headers.TryGetValue("Sec-WebSocket-Accept", out var accepts)
            || accepts.Count != 1
            || !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(accepts[0])))
        {
            throw new InvalidDataException("WebSocket handshake accept mismatch");
        }
        if (headers.ContainsKey("Sec-WebSocket-Extensions")
            || headers.ContainsKey("Sec-WebSocket-Protocol"))
        {
            throw new InvalidDataException("WebSocket server selected an unrequested extension or protocol");
        }
    }

    private static bool HeaderHasToken(Dictionary<string, List<string>> headers,
        string name, string expected)
    {
        return headers.TryGetValue(name, out var values)
               && values.SelectMany(value => value.Split(','))
                   .Any(value => value.Trim().Equals(expected, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSafeHeader(string name, string value)
    {
        if (string.IsNullOrWhiteSpace(name)
            || name.Any(character => !IsTokenCharacter(character))
            || name.IndexOfAny(['\r', '\n']) >= 0
            || value.IndexOfAny(['\r', '\n']) >= 0)
        {
            return false;
        }
        return true;
    }

    private static bool IsTokenCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character)
        || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-'
            or '.' or '^' or '_' or '`' or '|' or '~';

    internal static bool AcceptLocalCertificate(object sender, X509Certificate? certificate,
        X509Chain? chain, SslPolicyErrors sslPolicyErrors) => true;

    private async ValueTask WriteFrameLockedAsync(
        RawWebSocketFrame frame, CancellationToken cancellationToken)
    {
        if (frame.Opcode == Specus.Protocol.WebSocketSpecusFrame.OpcodeClose && _closeSent)
        {
            return;
        }
        var lengthBytes = frame.Payload.Length < 126 ? 0 : frame.Payload.Length <= ushort.MaxValue ? 2 : 8;
        var packet = new byte[2 + lengthBytes + 4 + frame.Payload.Length];
        packet[0] = (byte)(frame.Opcode | ((frame.Rsv & 7) << 4)
            | (frame.FinalFragment ? 0x80 : 0));
        var offset = 2;
        if (lengthBytes == 0)
        {
            packet[1] = (byte)(0x80 | frame.Payload.Length);
        }
        else if (lengthBytes == 2)
        {
            packet[1] = 0x80 | 126;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset, 2), (ushort)frame.Payload.Length);
            offset += 2;
        }
        else
        {
            packet[1] = 0x80 | 127;
            BinaryPrimitives.WriteUInt64BigEndian(packet.AsSpan(offset, 8), (ulong)frame.Payload.Length);
            offset += 8;
        }

        var mask = packet.AsSpan(offset, 4);
        RandomNumberGenerator.Fill(mask);
        offset += 4;
        for (var index = 0; index < frame.Payload.Length; index++)
        {
            packet[offset + index] = (byte)(frame.Payload[index] ^ mask[index & 3]);
        }
        await _stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (frame.Opcode == Specus.Protocol.WebSocketSpecusFrame.OpcodeClose)
        {
            _closeSent = true;
        }
    }

    private static void ValidateFrameHeader(byte opcode, bool finalFragment, byte rsv, ulong payloadLength)
    {
        if (opcode is not (0x0 or 0x1 or 0x2 or 0x8 or 0x9 or 0xA))
        {
            throw new InvalidDataException($"unsupported WebSocket opcode {opcode}");
        }
        if (rsv != 0)
        {
            throw new InvalidDataException("unexpected WebSocket RSV bits");
        }
        if (opcode >= 0x8 && (!finalFragment || rsv != 0 || payloadLength > 125))
        {
            throw new InvalidDataException("invalid fragmented WebSocket control frame");
        }
    }

    private static void ValidateFramePayload(RawWebSocketFrame frame)
    {
        if (frame.Opcode != Specus.Protocol.WebSocketSpecusFrame.OpcodeClose)
        {
            return;
        }
        if (frame.Payload.Length == 1)
        {
            throw new InvalidDataException("invalid WebSocket close payload");
        }
        if (frame.Payload.Length == 0)
        {
            return;
        }
        var code = BinaryPrimitives.ReadUInt16BigEndian(frame.Payload);
        if (code is < 1000 or >= 5000 or 1004 or 1005 or 1006 or 1015)
        {
            throw new InvalidDataException("invalid WebSocket close code");
        }
        try
        {
            _ = new UTF8Encoding(false, true).GetString(frame.Payload, 2,
                frame.Payload.Length - 2);
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidDataException("invalid WebSocket close reason UTF-8", ex);
        }
    }

    private static void ValidateFragmentSequence(RawWebSocketFrame frame,
        FragmentValidationState state)
    {
        if (frame.Opcode >= Specus.Protocol.WebSocketSpecusFrame.OpcodeClose)
        {
            return;
        }
        if (frame.Opcode == Specus.Protocol.WebSocketSpecusFrame.OpcodeContinuation)
        {
            if (!state.FragmentOpen)
            {
                throw new InvalidDataException("orphan WebSocket continuation frame");
            }
            if (state.TextMessage)
            {
                ValidateUtf8Payload(frame.Payload, frame.FinalFragment, state);
            }
            if (frame.FinalFragment)
            {
                state.Reset();
            }
            return;
        }
        if (state.FragmentOpen)
        {
            throw new InvalidDataException(
                "new WebSocket data frame before fragmented message completed");
        }
        state.TextMessage = frame.Opcode == Specus.Protocol.WebSocketSpecusFrame.OpcodeText;
        state.FragmentOpen = !frame.FinalFragment;
        if (state.TextMessage)
        {
            ValidateUtf8Payload(frame.Payload, frame.FinalFragment, state);
        }
        if (frame.FinalFragment)
        {
            state.Reset();
        }
    }

    private static void ValidateUtf8Payload(ReadOnlySpan<byte> payload, bool finalFragment,
        FragmentValidationState state)
    {
        var offset = 0;
        if (state.PendingUtf8Count > 0)
        {
            Span<byte> prefix = stackalloc byte[4];
            state.PendingUtf8.AsSpan(0, state.PendingUtf8Count).CopyTo(prefix);
            var count = state.PendingUtf8Count;
            while (true)
            {
                var status = Rune.DecodeFromUtf8(prefix[..count], out _, out _);
                if (status == OperationStatus.Done)
                {
                    state.PendingUtf8Count = 0;
                    break;
                }
                if (status == OperationStatus.InvalidData)
                {
                    throw new InvalidDataException("invalid WebSocket text UTF-8");
                }
                if (offset >= payload.Length)
                {
                    if (finalFragment)
                    {
                        throw new InvalidDataException("truncated WebSocket text UTF-8");
                    }
                    prefix[..count].CopyTo(state.PendingUtf8);
                    state.PendingUtf8Count = count;
                    return;
                }
                prefix[count++] = payload[offset++];
            }
        }
        while (offset < payload.Length)
        {
            var status = Rune.DecodeFromUtf8(payload[offset..], out _, out var consumed);
            if (status == OperationStatus.Done)
            {
                offset += consumed;
                continue;
            }
            if (status == OperationStatus.InvalidData)
            {
                throw new InvalidDataException("invalid WebSocket text UTF-8");
            }
            var remaining = payload.Length - offset;
            payload[offset..].CopyTo(state.PendingUtf8);
            state.PendingUtf8Count = remaining;
            if (finalFragment)
            {
                throw new InvalidDataException("truncated WebSocket text UTF-8");
            }
            return;
        }
        if (finalFragment && state.PendingUtf8Count != 0)
        {
            throw new InvalidDataException("truncated WebSocket text UTF-8");
        }
    }

    private sealed class FragmentValidationState
    {
        public bool FragmentOpen { get; set; }
        public bool TextMessage { get; set; }
        public byte[] PendingUtf8 { get; } = new byte[4];
        public int PendingUtf8Count { get; set; }

        public void Reset()
        {
            FragmentOpen = false;
            TextMessage = false;
            PendingUtf8Count = 0;
        }
    }

    private static async ValueTask<bool> TryReadExactlyAsync(Stream stream, Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                if (offset == 0)
                {
                    return false;
                }
                throw new EndOfStreamException("truncated WebSocket frame");
            }
            offset += read;
        }
        return true;
    }

    private static async ValueTask ReadExactlyAsync(Stream stream, Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        if (!await TryReadExactlyAsync(stream, destination, cancellationToken).ConfigureAwait(false))
        {
            throw new EndOfStreamException("truncated WebSocket frame");
        }
    }

    private void ThrowIfDisposed()
    {
        if (!IsOpen)
        {
            throw new ObjectDisposedException(nameof(RawWebSocketConnection));
        }
    }
}

internal sealed record RawWebSocketFrame(
    byte Opcode,
    bool FinalFragment,
    byte Rsv,
    byte[] Payload);
