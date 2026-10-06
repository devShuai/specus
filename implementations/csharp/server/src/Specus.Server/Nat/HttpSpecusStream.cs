using System.Threading.Channels;
using Specus.Protocol.Flow;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;

namespace Specus.Server.Nat;

internal readonly record struct HttpStreamReadResult(
    byte[]? Data, Dictionary<string, object?>? Metadata, bool End);

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

    private long _receiveCredit = StreamSendWindow.InitialBytes;
    private long _receiveOutstanding;
    private bool _responseHead;
    private bool _responseEnded;
    private bool _discardBody;
    private int _closed;

    public HttpSpecusStream(SpecusConnectionContext context, uint streamId,
        Action<uint, HttpSpecusStream> onClose)
    {
        _context = context;
        StreamId = streamId;
        _onClose = onClose;
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
        var item = await _events.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
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
        var item = await _events.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
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
        if (Volatile.Read(ref _closed) != 0)
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

    public bool OnResponseHead(Dictionary<string, object?>? metadata)
    {
        lock (_stateLock)
        {
            if (_responseHead || _responseEnded)
            {
                return false;
            }
            _responseHead = true;
            if (Enqueue(new HttpStreamEvent(HttpStreamEventKind.Head, Clone(metadata), null, null)))
            {
                return true;
            }
            _responseHead = false;
            return false;
        }
    }

    public bool OnResponseData(byte[]? data)
    {
        if (data is not { Length: > 0 })
        {
            return false;
        }
        lock (_stateLock)
        {
            if (!_responseHead || _responseEnded || data.Length > _receiveCredit)
            {
                return false;
            }
            _receiveCredit -= data.Length;
            if (_discardBody)
            {
                return true;
            }
            _receiveOutstanding += data.Length;
            if (Enqueue(new HttpStreamEvent(HttpStreamEventKind.Data, null, data.ToArray(), null)))
            {
                return true;
            }
            _receiveCredit += data.Length;
            _receiveOutstanding -= data.Length;
            return false;
        }
    }

    public bool OnResponseEnd(Dictionary<string, object?>? metadata)
    {
        lock (_stateLock)
        {
            if (!_responseHead || _responseEnded)
            {
                return false;
            }
            _responseEnded = true;
            if (_discardBody
                || Enqueue(new HttpStreamEvent(HttpStreamEventKind.End, Clone(metadata), null, null)))
            {
                return true;
            }
            _responseEnded = false;
            return false;
        }
    }

    public bool OnReset(uint code, string? reason, string? failure = null)
    {
        var error = new HttpStreamResetException(code, reason, failure);
        var written = Enqueue(new HttpStreamEvent(HttpStreamEventKind.Reset, null, null, error));
        Close();
        return written;
    }

    /// <summary>
    /// Ends the stream because its data connection is gone. Readers see the same reset as before,
    /// marked <see cref="HttpStreamResetException.LinkLost"/> so it is not mistaken for a client RST.
    /// </summary>
    public void OnLinkLost()
    {
        Enqueue(new HttpStreamEvent(HttpStreamEventKind.Reset, null, null,
            new HttpStreamResetException(0, "control channel closed", linkLost: true)));
        Close();
    }

    /// <summary>
    /// For a reader that only wants the response head (the connectivity check): response DATA and
    /// FIN are accepted but never queued, so a body relayed before the server's RST lands can
    /// neither fill the event queue nor earn WINDOW_UPDATE credit. DATA is still charged against
    /// the receive window, so a peer overrunning it remains a protocol violation.
    /// </summary>
    public void DiscardResponseBody()
    {
        lock (_stateLock)
        {
            _discardBody = true;
        }
    }

    public bool AddSendCredit(uint credit) => _sendWindow.Add(credit);

    public ValueTask DisposeAsync()
    {
        Close();
        return ValueTask.CompletedTask;
    }

    private bool Enqueue(HttpStreamEvent item) =>
        Volatile.Read(ref _closed) == 0 && _events.Writer.TryWrite(item);

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
