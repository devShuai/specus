using System.Net.WebSockets;
using System.Text;
using Microsoft.Extensions.Logging;
using Specus.Client.Control;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Protocol.Flow;

namespace Specus.Client.Nat;

internal enum WebSocketPumpResult
{
    Completed,
    CloseCreditTimedOut,
}

/// <summary>
/// One local WebSocket connection bridged through NAT <c>DATA</c> frames using mandatory SWS2.
/// </summary>
internal sealed class WebSocketSpecusChannel : IAsyncDisposable
{
    private const int BufferSize = 16 * 1024;
    private const int MaxMessageBytes = 16 * 1024 * 1024;
    private static readonly TimeSpan DefaultCloseSendTimeout = TimeSpan.FromSeconds(5);

    private readonly ClientWebSocket _socket;
    private readonly FrameWriter _controlWriter;
    private readonly ILogger _logger;
    private readonly Action<WebSocketSpecusChannel> _onClosed;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ManualResetEventSlim _writableGate = new(initialState: true);
    private readonly StreamSendWindow _sendWindow;
    private readonly TimeSpan _closeSendTimeout;
    private WebSocketMessageType? _incomingFragmentType;

    public WebSocketSpecusChannel(
        uint streamId,
        string channelId,
        ClientWebSocket socket,
        FrameWriter controlWriter,
        ILogger logger,
        Action<WebSocketSpecusChannel> onClosed,
        StreamSendWindow? sendWindow = null,
        TimeSpan? closeSendTimeout = null)
    {
        StreamId = streamId;
        ChannelId = channelId;
        _socket = socket;
        _controlWriter = controlWriter;
        _logger = logger;
        _onClosed = onClosed;
        _sendWindow = sendWindow ?? new StreamSendWindow();
        _closeSendTimeout = closeSendTimeout ?? DefaultCloseSendTimeout;
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

    public async Task<WebSocketPumpResult> PumpAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken);
        var token = linked.Token;
        var buffer = new byte[BufferSize];
        var messageBytes = 0;
        var continuation = false;
        var completion = WebSocketPumpResult.Completed;
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
                    using var closeCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    closeCts.CancelAfter(_closeSendTimeout);
                    try
                    {
                        await SendFrameAsync(new WebSocketSpecusFrame(
                            WebSocketSpecusFrame.OpcodeClose, true, 0, closeCode, reason), closeCts.Token)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested
                                                             && closeCts.IsCancellationRequested)
                    {
                        completion = WebSocketPumpResult.CloseCreditTimedOut;
                        _logger.LogDebug(
                            "ws channel {channel}: timed out waiting for CLOSE send credit", ChannelId);
                    }
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
                    ? WebSocketSpecusFrame.OpcodeContinuation
                    : result.MessageType == WebSocketMessageType.Text
                        ? WebSocketSpecusFrame.OpcodeText
                        : WebSocketSpecusFrame.OpcodeBinary;
                try
                {
                    await SendFrameAsync(new WebSocketSpecusFrame(
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
        return completion;
    }

    public async ValueTask WriteAsync(byte[] data, CancellationToken cancellationToken)
    {
        if (_socket.State != WebSocketState.Open)
        {
            return;
        }
        try
        {
            var frame = WebSocketSpecusFrame.Decode(data);
            if (frame.Rsv != 0)
            {
                throw new InvalidDataException("ClientWebSocket endpoint did not negotiate RSV extensions");
            }
            if (frame.Opcode == WebSocketSpecusFrame.OpcodePing)
            {
                // ClientWebSocket cannot emit a native ping to the local upstream.  Preserve
                // remote liveness at the tunnel boundary by returning the matching pong.
                await SendFrameAsync(new WebSocketSpecusFrame(
                    WebSocketSpecusFrame.OpcodePong, true, 0, 0, frame.Payload), cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
            if (frame.Opcode == WebSocketSpecusFrame.OpcodePong)
            {
                // ClientWebSocket consumes local control frames internally; a remote pong is
                // therefore safely consumed at this boundary as well.
                return;
            }
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (frame.Opcode == WebSocketSpecusFrame.OpcodeClose)
                {
                    var status = frame.CloseCode == 0
                        ? WebSocketCloseStatus.Empty
                        : (WebSocketCloseStatus)frame.CloseCode;
                    var description = frame.CloseCode == 0
                        ? null
                        : Encoding.UTF8.GetString(frame.Payload);
                    await _socket.CloseOutputAsync(
                        status, description, cancellationToken).ConfigureAwait(false);
                    return;
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

    private async Task SendFrameAsync(WebSocketSpecusFrame frame, CancellationToken token)
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

    private WebSocketMessageType ResolveIncomingMessageType(WebSocketSpecusFrame frame)
    {
        if (frame.Opcode == WebSocketSpecusFrame.OpcodeContinuation)
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
            WebSocketSpecusFrame.OpcodeText => WebSocketMessageType.Text,
            WebSocketSpecusFrame.OpcodeBinary => WebSocketMessageType.Binary,
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
