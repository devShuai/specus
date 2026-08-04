using System.Buffers;
using System.Buffers.Binary;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;
using Specus.Protocol;

namespace Specus.Server.Http;

/// <summary>
/// RFC 6455 server transport over ASP.NET's raw HTTP/1.1 upgrade stream. Kestrel has already
/// terminated HTTPS before this stream is exposed, so the same implementation serves ws and wss.
/// Keeping the wire frames visible is required by SWS2: the higher-level ASP.NET WebSocket API
/// hides RSV bits, physical continuation boundaries, and browser pong frames. Browser ping frames
/// are answered locally, matching the Java/Spring server endpoint, while browser pong frames remain
/// visible to the tunnel.
/// </summary>
internal sealed class RawServerWebSocketConnection : IAsyncDisposable
{
    private const int MaximumFrameBytes = 16 * 1024 * 1024;
    private const string WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private readonly Stream? _stream;
    private readonly WebSocket? _testHostWebSocket;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private int _aborted;
    private int _disposeState;
    private bool _closeSent;
    private bool _fallbackReadFragmentOpen;
    private WebSocketMessageType? _fallbackWriteMessageType;
    private readonly FragmentValidationState _readState = new();
    private readonly FragmentValidationState _writeState = new();

    private RawServerWebSocketConnection(Stream stream)
    {
        _stream = stream;
    }

    internal static RawServerWebSocketConnection CreateForTesting(Stream stream) => new(stream);

    private RawServerWebSocketConnection(WebSocket testHostWebSocket)
    {
        _testHostWebSocket = testHostWebSocket;
    }

    public bool IsOpen => Volatile.Read(ref _aborted) == 0;

    public static bool LooksLikeWebSocketUpgrade(HttpRequest request) =>
        HeaderHasToken(request.Headers.Upgrade, "websocket")
        || request.Headers.ContainsKey("Sec-WebSocket-Key")
        || request.Headers.ContainsKey("Sec-WebSocket-Version");

    public static async Task<RawServerWebSocketConnection> AcceptAsync(
        HttpContext context, CancellationToken cancellationToken)
    {
        if (!HttpMethods.IsGet(context.Request.Method)
            || !HeaderHasToken(context.Request.Headers.Connection, "upgrade")
            || !HeaderHasToken(context.Request.Headers.Upgrade, "websocket"))
        {
            throw new RawWebSocketHandshakeException(
                StatusCodes.Status400BadRequest, "无效的 WebSocket Upgrade 请求");
        }
        if (!HeaderHasToken(context.Request.Headers["Sec-WebSocket-Version"], "13"))
        {
            context.Response.Headers["Sec-WebSocket-Version"] = "13";
            throw new RawWebSocketHandshakeException(
                StatusCodes.Status426UpgradeRequired, "仅支持 WebSocket 版本 13");
        }
        if (!TryReadClientKey(context.Request.Headers["Sec-WebSocket-Key"], out var key))
        {
            throw new RawWebSocketHandshakeException(
                StatusCodes.Status400BadRequest, "无效的 Sec-WebSocket-Key");
        }

        var upgrade = context.Features.Get<IHttpUpgradeFeature>();
        if (upgrade is null || !upgrade.IsUpgradableRequest)
        {
            // Microsoft.AspNetCore.TestHost exposes only IHttpWebSocketFeature, not the raw
            // IHttpUpgradeFeature used by Kestrel. Keep the integration-test host usable while
            // production ws/wss connections always take the raw RFC 6455 path below.
            if (context.WebSockets.IsWebSocketRequest)
            {
                var webSocket = await context.WebSockets.AcceptWebSocketAsync()
                    .WaitAsync(cancellationToken).ConfigureAwait(false);
                return new RawServerWebSocketConnection(webSocket);
            }
            throw new RawWebSocketHandshakeException(
                StatusCodes.Status426UpgradeRequired, "当前 HTTP 连接不支持 WebSocket Upgrade");
        }

        var accept = Convert.ToBase64String(
            SHA1.HashData(Encoding.ASCII.GetBytes(key + WebSocketGuid)));
        context.Response.StatusCode = StatusCodes.Status101SwitchingProtocols;
        context.Response.Headers.Connection = "Upgrade";
        context.Response.Headers.Upgrade = "websocket";
        context.Response.Headers["Sec-WebSocket-Accept"] = accept;
        var stream = await upgrade.UpgradeAsync().WaitAsync(cancellationToken).ConfigureAwait(false);
        return new RawServerWebSocketConnection(stream);
    }

    public async ValueTask<RawServerWebSocketFrame?> ReadFrameAsync(
        CancellationToken cancellationToken)
    {
        ThrowIfClosed();
        if (_testHostWebSocket is not null)
        {
            return await ReadTestHostFrameAsync(_testHostWebSocket, cancellationToken)
                .ConfigureAwait(false);
        }

        while (true)
        {
            var frame = await ReadRawFrameAsync(cancellationToken).ConfigureAwait(false);
            if (frame is null || frame.Opcode != WebSocketSpecusFrame.OpcodePing)
            {
                return frame;
            }

            // Servlet WebSocket containers consume an inbound browser PING and emit a same-payload
            // PONG locally. Keep that endpoint contract on Kestrel's raw-upgrade path: the write
            // lock serializes this response with client-to-browser tunnel writes, and the PING is
            // deliberately not exposed to DirectHttpEndpoints for SWS2 forwarding.
            await WriteFrameAsync(new RawServerWebSocketFrame(
                    WebSocketSpecusFrame.OpcodePong, true, 0, frame.Payload), cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async ValueTask<RawServerWebSocketFrame?> ReadRawFrameAsync(
        CancellationToken cancellationToken)
    {

        var header = new byte[2];
        if (!await TryReadExactlyAsync(_stream!, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var finalFragment = (header[0] & 0x80) != 0;
        var rsv = (byte)((header[0] >> 4) & 0x07);
        var opcode = (byte)(header[0] & 0x0f);
        if ((header[1] & 0x80) == 0)
        {
            throw new InvalidDataException("browser WebSocket frame must be masked");
        }

        ulong length = (uint)(header[1] & 0x7f);
        if (length == 126)
        {
            var extended = new byte[2];
            await ReadExactlyAsync(_stream!, extended, cancellationToken).ConfigureAwait(false);
            length = BinaryPrimitives.ReadUInt16BigEndian(extended);
            if (length < 126)
            {
                throw new InvalidDataException("non-minimal WebSocket frame length");
            }
        }
        else if (length == 127)
        {
            var extended = new byte[8];
            await ReadExactlyAsync(_stream!, extended, cancellationToken).ConfigureAwait(false);
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

        var mask = new byte[4];
        await ReadExactlyAsync(_stream!, mask, cancellationToken).ConfigureAwait(false);
        var payload = new byte[(int)length];
        await ReadExactlyAsync(_stream!, payload, cancellationToken).ConfigureAwait(false);
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] ^= mask[index & 3];
        }
        var frame = new RawServerWebSocketFrame(opcode, finalFragment, rsv, payload);
        ValidateFramePayload(frame);
        ValidateFragmentSequence(frame, _readState);
        return frame;
    }

    public async ValueTask WriteFrameAsync(
        RawServerWebSocketFrame frame, CancellationToken cancellationToken)
    {
        ThrowIfClosed();
        ValidateFrameHeader(frame.Opcode, frame.FinalFragment, frame.Rsv,
            (ulong)frame.Payload.Length);
        if (frame.Payload.Length > MaximumFrameBytes)
        {
            throw new InvalidDataException("WebSocket frame exceeds limit");
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfClosed();
            ValidateFramePayload(frame);
            ValidateFragmentSequence(frame, _writeState);
            if (_testHostWebSocket is null)
            {
                await WriteFrameLockedAsync(frame, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await WriteTestHostFrameLockedAsync(_testHostWebSocket, frame, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async ValueTask ReplyToCloseAsync(
        RawServerWebSocketFrame frame, CancellationToken cancellationToken)
    {
        if (frame.Opcode != WebSocketSpecusFrame.OpcodeClose || !IsOpen)
        {
            return;
        }
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfClosed();
            if (!_closeSent)
            {
                if (_testHostWebSocket is null)
                {
                    await WriteFrameLockedAsync(frame, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await WriteTestHostFrameLockedAsync(_testHostWebSocket, frame, cancellationToken)
                        .ConfigureAwait(false);
                }
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
        try
        {
            _testHostWebSocket?.Abort();
            _testHostWebSocket?.Dispose();
            _stream?.Dispose();
        }
        catch { /* connection already closed */ }
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

    private async ValueTask WriteFrameLockedAsync(
        RawServerWebSocketFrame frame, CancellationToken cancellationToken)
    {
        if (frame.Opcode == WebSocketSpecusFrame.OpcodeClose && _closeSent)
        {
            return;
        }
        var lengthBytes = frame.Payload.Length < 126 ? 0 : frame.Payload.Length <= ushort.MaxValue ? 2 : 8;
        var packet = new byte[2 + lengthBytes + frame.Payload.Length];
        packet[0] = (byte)(frame.Opcode | ((frame.Rsv & 7) << 4)
            | (frame.FinalFragment ? 0x80 : 0));
        var offset = 2;
        if (lengthBytes == 0)
        {
            packet[1] = (byte)frame.Payload.Length;
        }
        else if (lengthBytes == 2)
        {
            packet[1] = 126;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset, 2),
                (ushort)frame.Payload.Length);
            offset += 2;
        }
        else
        {
            packet[1] = 127;
            BinaryPrimitives.WriteUInt64BigEndian(packet.AsSpan(offset, 8),
                (ulong)frame.Payload.Length);
            offset += 8;
        }
        frame.Payload.CopyTo(packet, offset);
        await _stream!.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (frame.Opcode == WebSocketSpecusFrame.OpcodeClose)
        {
            _closeSent = true;
        }
    }

    private async ValueTask<RawServerWebSocketFrame?> ReadTestHostFrameAsync(
        WebSocket webSocket, CancellationToken cancellationToken)
    {
        var payload = new byte[MaximumFrameBytes];
        var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(payload), cancellationToken)
            .ConfigureAwait(false);
        if (result.MessageType == WebSocketMessageType.Close)
        {
            var reason = Encoding.UTF8.GetBytes(result.CloseStatusDescription ?? string.Empty);
            byte[] closePayload = result.CloseStatus is null
                ? []
                : [(byte)((ushort)result.CloseStatus.Value >> 8),
                    (byte)(ushort)result.CloseStatus.Value, .. reason];
            var close = new RawServerWebSocketFrame(WebSocketSpecusFrame.OpcodeClose, true, 0,
                closePayload);
            ValidateFramePayload(close);
            return close;
        }
        if (result.Count == 0 && webSocket.State is WebSocketState.Aborted or WebSocketState.Closed)
        {
            return null;
        }

        var opcode = _fallbackReadFragmentOpen
            ? WebSocketSpecusFrame.OpcodeContinuation
            : result.MessageType == WebSocketMessageType.Text
                ? WebSocketSpecusFrame.OpcodeText
                : WebSocketSpecusFrame.OpcodeBinary;
        _fallbackReadFragmentOpen = !result.EndOfMessage;
        var frame = new RawServerWebSocketFrame(opcode, result.EndOfMessage, 0,
            payload.AsSpan(0, result.Count).ToArray());
        ValidateFragmentSequence(frame, _readState);
        return frame;
    }

    private async ValueTask WriteTestHostFrameLockedAsync(WebSocket webSocket,
        RawServerWebSocketFrame frame, CancellationToken cancellationToken)
    {
        if (frame.Opcode == WebSocketSpecusFrame.OpcodeClose)
        {
            if (_closeSent)
            {
                return;
            }
            var (status, reason) = ParseClosePayload(frame.Payload);
            await webSocket.CloseOutputAsync(status, reason, cancellationToken)
                .ConfigureAwait(false);
            _closeSent = true;
            return;
        }
        if (frame.Opcode is WebSocketSpecusFrame.OpcodePing or WebSocketSpecusFrame.OpcodePong)
        {
            // System.Net.WebSockets intentionally hides control frames. This branch exists only
            // for TestHost; Kestrel uses WriteFrameLockedAsync and preserves them exactly.
            return;
        }

        WebSocketMessageType messageType;
        if (frame.Opcode == WebSocketSpecusFrame.OpcodeText)
        {
            messageType = WebSocketMessageType.Text;
            _fallbackWriteMessageType = messageType;
        }
        else if (frame.Opcode == WebSocketSpecusFrame.OpcodeBinary)
        {
            messageType = WebSocketMessageType.Binary;
            _fallbackWriteMessageType = messageType;
        }
        else
        {
            messageType = _fallbackWriteMessageType
                ?? throw new InvalidDataException("orphan WebSocket continuation frame");
        }
        await webSocket.SendAsync(frame.Payload, messageType, frame.FinalFragment,
            cancellationToken).ConfigureAwait(false);
        if (frame.FinalFragment)
        {
            _fallbackWriteMessageType = null;
        }
    }

    private static (WebSocketCloseStatus Status, string Reason) ParseClosePayload(byte[] payload)
    {
        if (payload.Length == 0)
        {
            return (WebSocketCloseStatus.NormalClosure, string.Empty);
        }
        if (payload.Length == 1)
        {
            throw new InvalidDataException("invalid WebSocket close payload");
        }
        return ((WebSocketCloseStatus)BinaryPrimitives.ReadUInt16BigEndian(payload),
            Encoding.UTF8.GetString(payload, 2, payload.Length - 2));
    }

    private static bool TryReadClientKey(StringValues values, out string key)
    {
        key = string.Empty;
        if (values.Count != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            return false;
        }
        try
        {
            var decoded = Convert.FromBase64String(values[0]!.Trim());
            if (decoded.Length != 16)
            {
                return false;
            }
            key = values[0]!.Trim();
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool HeaderHasToken(StringValues values, string expected) =>
        values.SelectMany(value => (value ?? string.Empty).Split(','))
            .Any(value => value.Trim().Equals(expected, StringComparison.OrdinalIgnoreCase));

    private static void ValidateFrameHeader(
        byte opcode, bool finalFragment, byte rsv, ulong payloadLength)
    {
        if (opcode is not (0x0 or 0x1 or 0x2 or 0x8 or 0x9 or 0xA))
        {
            throw new InvalidDataException($"unsupported WebSocket opcode {opcode}");
        }
        if (rsv != 0)
        {
            // This endpoint does not negotiate Sec-WebSocket-Extensions, therefore RFC 6455
            // requires all reserved bits to remain zero.
            throw new InvalidDataException("unexpected WebSocket RSV bits");
        }
        if (opcode >= 0x8 && (!finalFragment || rsv != 0 || payloadLength > 125))
        {
            throw new InvalidDataException("invalid fragmented WebSocket control frame");
        }
    }

    private static void ValidateFramePayload(RawServerWebSocketFrame frame)
    {
        if (frame.Opcode != WebSocketSpecusFrame.OpcodeClose)
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
            _ = StrictUtf8.GetString(frame.Payload, 2, frame.Payload.Length - 2);
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidDataException("invalid WebSocket close reason UTF-8", ex);
        }
    }

    private static void ValidateFragmentSequence(RawServerWebSocketFrame frame,
        FragmentValidationState state)
    {
        if (frame.Opcode >= WebSocketSpecusFrame.OpcodeClose)
        {
            return;
        }
        if (frame.Opcode == WebSocketSpecusFrame.OpcodeContinuation)
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

        state.TextMessage = frame.Opcode == WebSocketSpecusFrame.OpcodeText;
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

    private static async ValueTask<bool> TryReadExactlyAsync(
        Stream stream, Memory<byte> destination, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken)
                .ConfigureAwait(false);
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

    private static async ValueTask ReadExactlyAsync(
        Stream stream, Memory<byte> destination, CancellationToken cancellationToken)
    {
        if (!await TryReadExactlyAsync(stream, destination, cancellationToken).ConfigureAwait(false))
        {
            throw new EndOfStreamException("truncated WebSocket frame");
        }
    }

    private void ThrowIfClosed()
    {
        if (!IsOpen)
        {
            throw new ObjectDisposedException(nameof(RawServerWebSocketConnection));
        }
    }
}

internal sealed record RawServerWebSocketFrame(
    byte Opcode,
    bool FinalFragment,
    byte Rsv,
    byte[] Payload);

internal sealed class RawWebSocketHandshakeException(int statusCode, string message)
    : Exception(message)
{
    public int StatusCode { get; } = statusCode;
}
