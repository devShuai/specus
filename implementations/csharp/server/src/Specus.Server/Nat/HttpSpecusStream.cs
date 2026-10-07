using System.Threading.Channels;
using Specus.Protocol.Flow;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;

namespace Specus.Server.Nat;

internal readonly record struct HttpStreamReadResult(
    byte[]? Data, Dictionary<string, object?>? Metadata, bool End);

/// <summary>What became of one response frame the client sent on an HTTP stream.</summary>
internal enum HttpStreamIngestResult
{
    Accepted,

    /// <summary>
    /// The stream is already closed (Close() ran; its removal from the session may still be under
    /// way): the frame is late and is answered as a closed stream's, not as a protocol violation.
    /// </summary>
    Closed,

    /// <summary>The reader fell behind and the event queue is full: only this stream is reset.</summary>
    QueueFull,

    /// <summary>
    /// The frame breaks the stream's state machine: DATA before the response head, a frame after
    /// the response ended, DATA beyond the receive window or a second response head.
    /// </summary>
    ProtocolViolation,
}

/// <summary>
/// Terminal error of an HTTP stream that was reset. <see cref="Reason"/> is free text, for a
/// client RST supplied by the client, and can carry the target URL, internal hosts or the raw
/// query; the exception message therefore omits it so it cannot reach a public response.
/// </summary>
internal sealed class HttpStreamResetException(uint code, string? reason, string? failure = null,
    bool linkLost = false)
    : IOException("HTTP stream reset")
{
    public uint Code { get; } = code;

    public string Reason { get; } = reason ?? string.Empty;

    /// <summary>
    /// RST <c>metadata.failure</c> as the client sent it, null when absent or not a string. It is
    /// only meaningful on a connection whose session announced the HTTP route capability, and only
    /// the connectivity check reads it; the public path answers its fixed 502 either way.
    /// </summary>
    public string? Failure { get; } = failure;

    /// <summary>
    /// True when the data connection closed or was replaced before an answer, rather than the
    /// client resetting this stream.
    /// </summary>
    public bool LinkLost { get; } = linkLost;
}

/// <summary>One mandatory NAT stream v2 HTTP exchange.</summary>
internal sealed class HttpSpecusStream : IAsyncDisposable
{
    private const long MaximumWindow = StreamSendWindow.MaximumBytes;

    private readonly SpecusConnectionContext _context;
    private readonly Action<uint, HttpSpecusStream> _onClose;
    private readonly StreamSendWindow _sendWindow = new();
    private readonly Channel<HttpStreamEvent> _events = Channel.CreateBounded<HttpStreamEvent>(
        new BoundedChannelOptions(32)
        {
            // TryWrite must report saturation. DropWrite reports success while discarding the
            // new event, which can silently truncate an otherwise successful HTTP response.
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
        });
    private readonly object _stateLock = new();

    private readonly bool _discardBody;

    private long _receiveCredit = StreamSendWindow.InitialBytes;
    private long _receiveOutstanding;
    private bool _responseHead;
    private bool _responseEnded;
    private HttpStreamResetException? _resetAhead;
    private int _closed;

    /// <param name="discardResponseBody">
    /// For a reader that only wants the response head (the connectivity check): response DATA and
    /// FIN are accepted but never queued, so a body relayed before the server's RST lands can
    /// neither fill the event queue nor earn WINDOW_UPDATE credit. DATA is still charged against
    /// the receive window, so a peer overrunning it remains a protocol violation. It is fixed
    /// before the stream is registered, so it already holds for a response that overtakes OPEN.
    /// </param>
    public HttpSpecusStream(SpecusConnectionContext context, uint streamId,
        Action<uint, HttpSpecusStream> onClose, bool discardResponseBody = false)
    {
        _context = context;
        StreamId = streamId;
        _onClose = onClose;
        _discardBody = discardResponseBody;
    }

    public uint StreamId { get; }

    /// <summary>Client session that owns the data connection this stream runs on.</summary>
    public long? ConnectionSessionId => _context.ClientSessionId;

    /// <summary>True once the response FIN (or DATA with END_STREAM) has been accepted.</summary>
    public bool ResponseEnded
    {
        get
        {
            lock (_stateLock)
            {
                return _responseEnded;
            }
        }
    }

    public async ValueTask SendDataAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (data.IsEmpty)
        {
            return;
        }
        if (!await _sendWindow.ConsumeAsync(data.Length, cancellationToken).ConfigureAwait(false))
        {
            throw new IOException("HTTP stream send window is closed");
        }
        await _context.Writer.WriteAsync(new NatMessagePacket
        {
            NatMessageType = Protocol.NatMessageType.Data,
            StreamId = StreamId,
            Data = data.ToArray(),
        }, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask FinishRequestAsync(Dictionary<string, object?>? metadata,
        CancellationToken cancellationToken) =>
        _context.Writer.WriteAsync(new NatMessagePacket
        {
            NatMessageType = Protocol.NatMessageType.Fin,
            StreamId = StreamId,
            MetaData = metadata,
        }, cancellationToken);

    public async ValueTask<Dictionary<string, object?>> WaitResponseHeadAsync(
        CancellationToken cancellationToken)
    {
        var item = await ReadEventAsync(cancellationToken).ConfigureAwait(false);
        if (item.Error is not null)
        {
            throw item.Error;
        }
        if (item.Kind != HttpStreamEventKind.Head || item.Metadata is null)
        {
            throw new InvalidDataException("HTTP response did not start with OPEN");
        }
        return item.Metadata;
    }

    public async ValueTask<HttpStreamReadResult> ReadResponseAsync(CancellationToken cancellationToken)
    {
        var item = await ReadEventAsync(cancellationToken).ConfigureAwait(false);
        if (item.Error is not null)
        {
            throw item.Error;
        }
        return item.Kind switch
        {
            HttpStreamEventKind.Data => new HttpStreamReadResult(item.Data, null, false),
            HttpStreamEventKind.End => new HttpStreamReadResult(null, item.Metadata, true),
            _ => throw new InvalidDataException("unexpected HTTP stream event"),
        };
    }

    public ValueTask ConsumeResponseAsync(int bytes, CancellationToken cancellationToken)
    {
        if (bytes <= 0)
        {
            return ValueTask.CompletedTask;
        }
        lock (_stateLock)
        {
            if (bytes > _receiveOutstanding || _receiveCredit > MaximumWindow - bytes)
            {
                throw new InvalidDataException("HTTP response window overflow");
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
        if (IsClosed)
        {
            return;
        }
        try
        {
            await _context.Writer.WriteAsync(new NatMessagePacket
            {
                NatMessageType = Protocol.NatMessageType.Rst,
                StreamId = StreamId,
                Value = code,
                MetaData = new Dictionary<string, object?> { ["reason"] = reason },
            }, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Close();
        }
    }

    /// <summary>
    /// Resets the stream because its reader fell behind: the event queue is full while the client
    /// still has window. The RST goes to the client as from <see cref="ResetAsync"/>, and the
    /// reader meets the same <see cref="HttpStreamResetException"/> a client RST raises on its
    /// next read, ahead of the events still queued.
    /// </summary>
    public ValueTask ResetOverflowAsync(uint code, string reason, CancellationToken cancellationToken)
    {
        lock (_stateLock)
        {
            if (IsClosed)
            {
                return ValueTask.CompletedTask;
            }
            _resetAhead ??= new HttpStreamResetException(code, reason);
        }
        return ResetAsync(code, reason, cancellationToken);
    }

    public HttpStreamIngestResult OnResponseHead(Dictionary<string, object?>? metadata)
    {
        lock (_stateLock)
        {
            if (IsClosed)
            {
                return HttpStreamIngestResult.Closed;
            }
            if (_responseHead || _responseEnded)
            {
                return HttpStreamIngestResult.ProtocolViolation;
            }
            var result = Enqueue(new HttpStreamEvent(HttpStreamEventKind.Head, Clone(metadata), null, null));
            _responseHead = result == HttpStreamIngestResult.Accepted;
            return result;
        }
    }

    public HttpStreamIngestResult OnResponseData(byte[]? data)
    {
        lock (_stateLock)
        {
            if (IsClosed)
            {
                return HttpStreamIngestResult.Closed;
            }
            if (data is not { Length: > 0 } || !_responseHead || _responseEnded
                || data.Length > _receiveCredit)
            {
                return HttpStreamIngestResult.ProtocolViolation;
            }
            _receiveCredit -= data.Length;
            if (_discardBody)
            {
                return HttpStreamIngestResult.Accepted;
            }
            _receiveOutstanding += data.Length;
            var result = Enqueue(new HttpStreamEvent(HttpStreamEventKind.Data, null, data.ToArray(), null));
            if (result != HttpStreamIngestResult.Accepted)
            {
                _receiveCredit += data.Length;
                _receiveOutstanding -= data.Length;
            }
            return result;
        }
    }

    public HttpStreamIngestResult OnResponseEnd(Dictionary<string, object?>? metadata)
    {
        lock (_stateLock)
        {
            if (IsClosed)
            {
                return HttpStreamIngestResult.Closed;
            }
            if (!_responseHead || _responseEnded)
            {
                return HttpStreamIngestResult.ProtocolViolation;
            }
            var result = _discardBody
                ? HttpStreamIngestResult.Accepted
                : Enqueue(new HttpStreamEvent(HttpStreamEventKind.End, Clone(metadata), null, null));
            _responseEnded = result == HttpStreamIngestResult.Accepted;
            return result;
        }
    }

    /// <summary>
    /// A client RST always ends the stream. One that crosses the server's own close is late and
    /// changes nothing; one that finds the event queue full reaches the reader ahead of it.
    /// </summary>
    public void OnReset(uint code, string? reason, string? failure = null) =>
        Terminate(new HttpStreamResetException(code, reason, failure));

    /// <summary>
    /// Ends the stream because its data connection is gone. Readers see the same reset as before,
    /// marked <see cref="HttpStreamResetException.LinkLost"/> so it is not mistaken for a client RST.
    /// </summary>
    public void OnLinkLost() =>
        Terminate(new HttpStreamResetException(0, "control channel closed", linkLost: true));

    public bool AddSendCredit(uint credit) => _sendWindow.Add(credit);

    public ValueTask DisposeAsync()
    {
        Close();
        return ValueTask.CompletedTask;
    }

    private bool IsClosed => Volatile.Read(ref _closed) != 0;

    private HttpStreamIngestResult Enqueue(HttpStreamEvent item)
    {
        if (IsClosed)
        {
            return HttpStreamIngestResult.Closed;
        }
        if (_events.Writer.TryWrite(item))
        {
            return HttpStreamIngestResult.Accepted;
        }
        // Close() marks the stream before it completes the queue, so a write refused because the
        // queue was completed already reads as closed here.
        return IsClosed ? HttpStreamIngestResult.Closed : HttpStreamIngestResult.QueueFull;
    }

    private void Terminate(HttpStreamResetException error)
    {
        lock (_stateLock)
        {
            if (Enqueue(new HttpStreamEvent(HttpStreamEventKind.Reset, null, null, error))
                == HttpStreamIngestResult.QueueFull)
            {
                _resetAhead ??= error;
            }
        }
        Close();
    }

    private async ValueTask<HttpStreamEvent> ReadEventAsync(CancellationToken cancellationToken)
    {
        ThrowResetAhead();
        try
        {
            return await _events.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            ThrowResetAhead();
            throw;
        }
    }

    /// <summary>Throws the reset that could not wait behind the queued events, if there is one.</summary>
    private void ThrowResetAhead()
    {
        HttpStreamResetException? reset;
        lock (_stateLock)
        {
            reset = _resetAhead;
        }
        if (reset is not null)
        {
            throw reset;
        }
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

    private static Dictionary<string, object?>? Clone(Dictionary<string, object?>? metadata) =>
        metadata is null ? null : new Dictionary<string, object?>(metadata);

    private enum HttpStreamEventKind
    {
        Head,
        Data,
        End,
        Reset,
    }

    private readonly record struct HttpStreamEvent(HttpStreamEventKind Kind,
        Dictionary<string, object?>? Metadata, byte[]? Data, Exception? Error);
}
