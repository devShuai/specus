using System.Net.WebSockets;
using System.Text;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Protocol.Flow;

namespace ShuaiTunnel.Client.Nat;

/// <summary>
/// One local WebSocket connection bridged through NAT <c>DATA</c> frames using mandatory SWS2.
/// </summary>
internal sealed class WebSocketTunnelChannel : IAsyncDisposable
{
    private const int BufferSize = 16 * 1024;
    private const int MaxMessageBytes = 16 * 1024 * 1024;

    private readonly ClientWebSocket _socket;
    private readonly FrameWriter _controlWriter;
    private readonly ILogger _logger;
    private readonly Action<WebSocketTunnelChannel> _onClosed;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ManualResetEventSlim _writableGate = new(initialState: true);
    private readonly StreamSendWindow _sendWindow = new();
    private WebSocketMessageType? _incomingFragmentType;

    public WebSocketTunnelChannel(
        uint streamId,
        string channelId,
        ClientWebSocket socket,
        FrameWriter controlWriter,
        ILogger logger,
        Action<WebSocketTunnelChannel> onClosed)
    {
        StreamId = streamId;
        ChannelId = channelId;
        _socket = socket;
        _controlWriter = controlWriter;
        _logger = logger;
        _onClosed = onClosed;
    }

    public string ChannelId { get; }
    public uint StreamId { get; }

    public void SetControlWritable(bool writable)
    {
        if (writable)
        {
            _writableGate.Set();
        }
        else
        {
            _writableGate.Reset();
        }
    }

    public async Task PumpAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken);
        var token = linked.Token;
        var buffer = new byte[BufferSize];
        var messageBytes = 0;
        var continuation = false;
        try
        {
            while (!token.IsCancellationRequested && _socket.State == WebSocketState.Open)
            {
                if (!_writableGate.IsSet)
                {
                    _writableGate.Wait(TimeSpan.FromSeconds(1));
                    continue;
                }

                var result = await _socket.ReceiveAsync(buffer.AsMemory(), token).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    var reason = EncodeCloseReason(_socket.CloseStatusDescription);
                    var closeCode = _socket.CloseStatus is null ? (ushort)0 : (ushort)_socket.CloseStatus.Value;
                    await SendFrameAsync(new WebSocketTunnelFrame(
                        WebSocketTunnelFrame.OpcodeClose, true, 0, closeCode, reason), token).ConfigureAwait(false);
                    break;
                }
                if (result.MessageType is not WebSocketMessageType.Text and not WebSocketMessageType.Binary)
                {
                    continue;
                }

                messageBytes += result.Count;
                if (messageBytes > MaxMessageBytes)
                {
                    _logger.LogDebug("ws channel {channel}: local message exceeds limit", ChannelId);
                    break;
                }
                var opcode = continuation
                    ? WebSocketTunnelFrame.OpcodeContinuation
                    : result.MessageType == WebSocketMessageType.Text
                        ? WebSocketTunnelFrame.OpcodeText
                        : WebSocketTunnelFrame.OpcodeBinary;
                try
                {
                    await SendFrameAsync(new WebSocketTunnelFrame(
                        opcode, result.EndOfMessage, 0, 0, buffer.AsSpan(0, result.Count).ToArray()), token)
                        .ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug(ex, "ws channel {channel}: write to control failed", ChannelId);
                    break;
                }
                continuation = !result.EndOfMessage;
                if (result.EndOfMessage)
                {
                    messageBytes = 0;
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "ws channel {channel}: local pump aborted", ChannelId);
        }
        finally
        {
            _onClosed(this);
            await DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask WriteAsync(byte[] data, CancellationToken cancellationToken)
    {
        if (_socket.State != WebSocketState.Open)
        {
            return;
        }
        try
        {
            var frame = WebSocketTunnelFrame.Decode(data);
            if (frame.Rsv != 0)
            {
                throw new InvalidDataException("ClientWebSocket endpoint did not negotiate RSV extensions");
            }
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (frame.Opcode == WebSocketTunnelFrame.OpcodeClose)
                {
                    var status = frame.CloseCode == 0
                        ? WebSocketCloseStatus.NormalClosure
                        : (WebSocketCloseStatus)frame.CloseCode;
                    await _socket.CloseOutputAsync(
                        status, Encoding.UTF8.GetString(frame.Payload), cancellationToken).ConfigureAwait(false);
                    return;
                }
                if (frame.Opcode is WebSocketTunnelFrame.OpcodePing or WebSocketTunnelFrame.OpcodePong)
                {
                    throw new InvalidDataException("ClientWebSocket cannot emit explicit ping/pong frames");
                }
                var messageType = ResolveIncomingMessageType(frame);
                await _socket.SendAsync(
                    frame.Payload,
                    messageType,
                    frame.FinalFragment,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "ws channel {channel}: local write failed", ChannelId);
            Close();
        }
    }

    public void Close()
    {
        _sendWindow.Close();
        try { _cts.Cancel(); }
        catch (ObjectDisposedException) { }
        try { _socket.Abort(); }
        catch { /* best effort */ }
    }

    public bool AddSendCredit(uint credit) => _sendWindow.Add(credit);

    private async Task SendFrameAsync(WebSocketTunnelFrame frame, CancellationToken token)
    {
        var payload = frame.Encode();
        if (!await _sendWindow.ConsumeAsync(payload.Length, token).ConfigureAwait(false))
        {
            throw new OperationCanceledException("WebSocket stream send window was closed", token);
        }
        await _controlWriter.WriteAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = StreamId,
            Data = payload,
        }, token).ConfigureAwait(false);
    }

    private WebSocketMessageType ResolveIncomingMessageType(WebSocketTunnelFrame frame)
    {
        if (frame.Opcode == WebSocketTunnelFrame.OpcodeContinuation)
        {
            if (_incomingFragmentType is null)
            {
                throw new InvalidDataException("orphan SWS2 continuation frame");
            }
            var continuedType = _incomingFragmentType.Value;
            if (frame.FinalFragment)
            {
                _incomingFragmentType = null;
            }
            return continuedType;
        }

        var type = frame.Opcode switch
        {
            WebSocketTunnelFrame.OpcodeText => WebSocketMessageType.Text,
            WebSocketTunnelFrame.OpcodeBinary => WebSocketMessageType.Binary,
            _ => throw new InvalidDataException($"unsupported SWS2 data opcode {frame.Opcode}"),
        };
        if (_incomingFragmentType is not null)
        {
            throw new InvalidDataException("new SWS2 message before fragmented message completed");
        }
        if (!frame.FinalFragment)
        {
            _incomingFragmentType = type;
        }
        return type;
    }

    private static byte[] EncodeCloseReason(string? reason)
    {
        if (string.IsNullOrEmpty(reason))
        {
            return [];
        }
        var bytes = new byte[123];
        Encoding.UTF8.GetEncoder().Convert(
            reason.AsSpan(), bytes, true, out _, out var bytesUsed, out _);
        return bytes.AsSpan(0, bytesUsed).ToArray();
    }

    public ValueTask DisposeAsync()
    {
        Close();
        _socket.Dispose();
        _writeLock.Dispose();
        _writableGate.Dispose();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }
}
