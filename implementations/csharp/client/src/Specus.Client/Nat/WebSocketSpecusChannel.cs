using System.Buffers.Binary;
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
    private const int MaxMessageBytes = 16 * 1024 * 1024;
    private static readonly TimeSpan DefaultCloseSendTimeout = TimeSpan.FromSeconds(5);

    private readonly RawWebSocketConnection _socket;
    private readonly FrameWriter _controlWriter;
    private readonly ILogger _logger;
    private readonly Action<WebSocketSpecusChannel> _onClosed;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ManualResetEventSlim _writableGate = new(initialState: true);
    private readonly StreamSendWindow _sendWindow;
    private readonly TimeSpan _closeSendTimeout;
    private bool _localFragmentOpen;
    private bool _tunnelFragmentOpen;
    private int _localMessageBytes;
    private int _disposeState;

    public WebSocketSpecusChannel(
        uint streamId,
        string channelId,
        RawWebSocketConnection socket,
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
        var completion = WebSocketPumpResult.Completed;
        try
        {
            while (!token.IsCancellationRequested && _socket.IsOpen)
            {
                if (!_writableGate.IsSet)
                {
                    _writableGate.Wait(TimeSpan.FromSeconds(1));
                    continue;
                }

                var rawFrame = await _socket.ReadFrameAsync(token).ConfigureAwait(false);
                if (rawFrame is null)
                {
                    break;
                }
                ValidateLocalFragmentSequence(rawFrame);
                var (closeCode, payload) = SplitClosePayload(rawFrame);
                if (rawFrame.Opcode == WebSocketSpecusFrame.OpcodeClose)
                {
                    using var closeCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    closeCts.CancelAfter(_closeSendTimeout);
                    try
                    {
                        await SendRawFrameAsync(rawFrame, closeCode, payload, closeCts.Token)
                            .ConfigureAwait(false);
                        await _socket.ReplyToCloseAsync(rawFrame, closeCts.Token).ConfigureAwait(false);
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
                try
                {
                    await SendRawFrameAsync(rawFrame, closeCode, payload, token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug(ex, "ws channel {channel}: write to control failed", ChannelId);
                    break;
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
        if (!_socket.IsOpen)
        {
            return;
        }
        try
        {
            var frame = WebSocketSpecusFrame.Decode(data);
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ValidateTunnelFragmentSequence(frame);
                var payload = frame.Payload;
                if (frame.Opcode == WebSocketSpecusFrame.OpcodeClose)
                {
                    payload = frame.CloseCode == 0
                        ? []
                        : [
                            (byte)(frame.CloseCode >> 8),
                            (byte)frame.CloseCode,
                            .. payload,
                        ];
                }
                await _socket.WriteFrameAsync(new RawWebSocketFrame(
                    frame.Opcode, frame.FinalFragment, frame.Rsv, payload), cancellationToken)
                    .ConfigureAwait(false);
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

    private async Task SendRawFrameAsync(RawWebSocketFrame rawFrame, ushort closeCode,
        byte[] payload, CancellationToken token)
    {
        var offset = 0;
        var first = true;
        do
        {
            var length = Math.Min(WebSocketSpecusFrame.MaxPayloadBytes, payload.Length - offset);
            var last = offset + length == payload.Length;
            await SendFrameAsync(new WebSocketSpecusFrame(
                first ? rawFrame.Opcode : WebSocketSpecusFrame.OpcodeContinuation,
                rawFrame.FinalFragment && last,
                first ? rawFrame.Rsv : (byte)0,
                first ? closeCode : (ushort)0,
                payload.AsSpan(offset, length).ToArray()), token).ConfigureAwait(false);
            offset += length;
            first = false;
        }
        while (offset < payload.Length);
    }

    private void ValidateLocalFragmentSequence(RawWebSocketFrame frame)
    {
        if (frame.Opcode >= WebSocketSpecusFrame.OpcodeClose)
        {
            return;
        }
        if (frame.Opcode == WebSocketSpecusFrame.OpcodeContinuation)
        {
            if (!_localFragmentOpen)
            {
                throw new InvalidDataException("orphan local WebSocket continuation frame");
            }
        }
        else if (_localFragmentOpen)
        {
            throw new InvalidDataException("new local WebSocket message before fragmented message completed");
        }
        _localMessageBytes = checked(_localMessageBytes + frame.Payload.Length);
        if (_localMessageBytes > MaxMessageBytes)
        {
            throw new InvalidDataException("local WebSocket message exceeds limit");
        }
        _localFragmentOpen = !frame.FinalFragment;
        if (frame.FinalFragment)
        {
            _localMessageBytes = 0;
        }
    }

    private void ValidateTunnelFragmentSequence(WebSocketSpecusFrame frame)
    {
        if (frame.Opcode >= WebSocketSpecusFrame.OpcodeClose)
        {
            return;
        }
        if (frame.Opcode == WebSocketSpecusFrame.OpcodeContinuation)
        {
            if (!_tunnelFragmentOpen)
            {
                throw new InvalidDataException("orphan SWS2 continuation frame");
            }
        }
        else if (_tunnelFragmentOpen)
        {
            throw new InvalidDataException("new SWS2 message before fragmented message completed");
        }
        _tunnelFragmentOpen = !frame.FinalFragment;
    }

    private static (ushort CloseCode, byte[] Payload) SplitClosePayload(RawWebSocketFrame frame)
    {
        if (frame.Opcode != WebSocketSpecusFrame.OpcodeClose || frame.Payload.Length == 0)
        {
            return (0, frame.Payload);
        }
        if (frame.Payload.Length == 1)
        {
            throw new InvalidDataException("invalid WebSocket close payload");
        }
        return (BinaryPrimitives.ReadUInt16BigEndian(frame.Payload), frame.Payload[2..]);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeState, 1) != 0)
        {
            return;
        }
        Close();
        await _socket.DisposeAsync().ConfigureAwait(false);
        _writeLock.Dispose();
        _writableGate.Dispose();
        _cts.Dispose();
    }
}
