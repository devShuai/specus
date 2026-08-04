using System.Threading.Channels;
using Specus.Protocol.Flow;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;

namespace Specus.Server.Nat;

internal readonly record struct WebSocketStreamReadResult(byte[]? Data, bool End);

internal enum WebSocketStreamIngestResult
{
    Accepted,
    Closed,
    QueueFull,
    FlowControlViolation,
}

/// <summary>
/// One browser-side WebSocket carried over mandatory NAT stream v2 DATA frames. The payload of
/// every DATA frame is an SWS2 envelope; this class owns stream flow control while the HTTP layer
/// owns WebSocket frame translation.
/// </summary>
internal sealed class WebSocketSpecusStream : IAsyncDisposable
{
    private const long MaximumWindow = StreamSendWindow.MaximumBytes;

    private readonly SpecusConnectionContext _context;
    private readonly Action<uint, WebSocketSpecusStream> _onClose;
    private readonly StreamSendWindow _sendWindow = new();
    private readonly Channel<byte[]> _events = Channel.CreateBounded<byte[]>(
        new BoundedChannelOptions(32)
        {
            // TryWrite must return false when the browser pump falls behind; DropWrite reports
            // success while discarding the new frame, which would silently corrupt WebSocket data.
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
        });
    private readonly object _stateLock = new();
    private readonly SemaphoreSlim _terminalWriteLock = new(1, 1);

    private long _receiveCredit = StreamSendWindow.InitialBytes;
    private long _receiveOutstanding;
    private Exception? _peerError;
    private bool _responseEnded;
    private int _outboundTerminalSent;
    private int _peerTerminal;
    private int _closed;

    public WebSocketSpecusStream(SpecusConnectionContext context, uint streamId,
        Action<uint, WebSocketSpecusStream> onClose)
    {
        _context = context;
        StreamId = streamId;
        _onClose = onClose;
    }

    public uint StreamId { get; }

    public bool PeerTerminated => Volatile.Read(ref _peerTerminal) != 0;

    public async ValueTask SendDataAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (data.IsEmpty)
        {
            return;
        }
        if (!await _sendWindow.ConsumeAsync(data.Length, cancellationToken).ConfigureAwait(false))
        {
            throw new IOException("WebSocket stream send window is closed");
        }
        await _context.Writer.WriteAsync(new NatMessagePacket
        {
            NatMessageType = Protocol.NatMessageType.Data,
            StreamId = StreamId,
            Data = data.ToArray(),
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask FinishAsync(CancellationToken cancellationToken)
    {
        await _terminalWriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _outboundTerminalSent) != 0)
            {
                return;
            }
            await _context.Writer.WriteAsync(new NatMessagePacket
            {
                NatMessageType = Protocol.NatMessageType.Fin,
                StreamId = StreamId,
            }, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _outboundTerminalSent, 1);
        }
        finally
        {
            _terminalWriteLock.Release();
        }
    }

    public async ValueTask<WebSocketStreamReadResult> ReadAsync(CancellationToken cancellationToken)
    {
        while (await _events.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (_events.Reader.TryRead(out var data))
            {
                return new WebSocketStreamReadResult(data, false);
            }
        }
        Exception? peerError;
        lock (_stateLock)
        {
            peerError = _peerError;
        }
        if (peerError is not null)
        {
            throw peerError;
        }
        return new WebSocketStreamReadResult(null, true);
    }

    public ValueTask ConsumeAsync(int bytes, CancellationToken cancellationToken)
    {
        if (bytes <= 0)
        {
            return ValueTask.CompletedTask;
        }
        lock (_stateLock)
        {
            if (bytes > _receiveOutstanding || _receiveCredit > MaximumWindow - bytes)
            {
                throw new InvalidDataException("WebSocket response window overflow");
            }
            _receiveOutstanding -= bytes;
            _receiveCredit += bytes;
        }
        return _context.Writer.WritePriorityAsync(new NatMessagePacket
        {
            NatMessageType = Protocol.NatMessageType.WindowUpdate,
            StreamId = StreamId,
            Value = checked((uint)bytes),
        }, cancellationToken);
    }

    public async ValueTask ResetAsync(uint code, string reason, CancellationToken cancellationToken)
    {
        var lockTaken = false;
        try
        {
            await _terminalWriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            lockTaken = true;
            if (Volatile.Read(ref _outboundTerminalSent) != 0)
            {
                return;
            }
            await _context.Writer.WriteAsync(new NatMessagePacket
            {
                NatMessageType = Protocol.NatMessageType.Rst,
                StreamId = StreamId,
                Value = code,
                MetaData = new Dictionary<string, object?> { ["reason"] = reason },
            }, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _outboundTerminalSent, 1);
        }
        finally
        {
            if (lockTaken)
            {
                _terminalWriteLock.Release();
            }
            Close();
        }
    }

    public WebSocketStreamIngestResult OnData(byte[]? data)
    {
        if (data is not { Length: > 0 })
        {
            return WebSocketStreamIngestResult.FlowControlViolation;
        }
        lock (_stateLock)
        {
            if (_responseEnded || Volatile.Read(ref _closed) != 0)
            {
                return WebSocketStreamIngestResult.Closed;
            }
            if (data.Length > _receiveCredit)
            {
                return WebSocketStreamIngestResult.FlowControlViolation;
            }
            _receiveCredit -= data.Length;
            _receiveOutstanding += data.Length;
        }
        if (_events.Writer.TryWrite(data.ToArray()))
        {
            return WebSocketStreamIngestResult.Accepted;
        }
        lock (_stateLock)
        {
            _receiveCredit += data.Length;
            _receiveOutstanding -= data.Length;
            return _responseEnded || Volatile.Read(ref _closed) != 0
                ? WebSocketStreamIngestResult.Closed
                : WebSocketStreamIngestResult.QueueFull;
        }
    }

    public void OnEnd()
    {
        lock (_stateLock)
        {
            if (_responseEnded)
            {
                return;
            }
            _responseEnded = true;
        }
        Interlocked.Exchange(ref _peerTerminal, 1);
        Close();
    }

    public void OnReset(string? reason)
    {
        Interlocked.Exchange(ref _peerTerminal, 1);
        lock (_stateLock)
        {
            if (!_responseEnded)
            {
                _responseEnded = true;
                _peerError = new IOException(string.IsNullOrWhiteSpace(reason)
                    ? "WebSocket stream reset by client"
                    : reason);
            }
        }
        Close();
    }

    public bool AddSendCredit(uint credit) => _sendWindow.Add(credit);

    public async ValueTask DisposeAsync()
    {
        if (Volatile.Read(ref _peerTerminal) == 0
            && Volatile.Read(ref _outboundTerminalSent) == 0)
        {
            var lockTaken = false;
            try
            {
                using var abortCts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                await _terminalWriteLock.WaitAsync(abortCts.Token).ConfigureAwait(false);
                lockTaken = true;
                if (Volatile.Read(ref _peerTerminal) == 0
                    && Volatile.Read(ref _outboundTerminalSent) == 0)
                {
                    await _context.Writer.WriteAsync(new NatMessagePacket
                    {
                        NatMessageType = Protocol.NatMessageType.Rst,
                        StreamId = StreamId,
                        Value = 31,
                        MetaData = new Dictionary<string, object?>
                        {
                            ["reason"] = "WebSocket ingress closed",
                        },
                    }, abortCts.Token).ConfigureAwait(false);
                    Volatile.Write(ref _outboundTerminalSent, 1);
                }
            }
            catch
            {
                // The data connection may be the reason the ingress is being disposed.
            }
            finally
            {
                if (lockTaken)
                {
                    _terminalWriteLock.Release();
                }
            }
        }
        Close();
    }

    private void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }
        _sendWindow.Close();
        _events.Writer.TryComplete();
        _onClose(StreamId, this);
    }
}
