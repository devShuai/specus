using System.Threading.Channels;
using ShuaiTunnel.Protocol.Flow;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.ControlChannel;

namespace ShuaiTunnel.Server.Nat;

internal readonly record struct HttpStreamReadResult(
    byte[]? Data, Dictionary<string, object?>? Metadata, bool End);

/// <summary>One mandatory NAT stream v2 HTTP exchange.</summary>
internal sealed class HttpTunnelStream : IAsyncDisposable
{
    private const long MaximumWindow = StreamSendWindow.MaximumBytes;

    private readonly TunnelConnectionContext _context;
    private readonly Action<uint, HttpTunnelStream> _onClose;
    private readonly StreamSendWindow _sendWindow = new();
    private readonly Channel<HttpStreamEvent> _events = Channel.CreateBounded<HttpStreamEvent>(
        new BoundedChannelOptions(32)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
            SingleWriter = false,
        });
    private readonly object _stateLock = new();

    private long _receiveCredit = StreamSendWindow.InitialBytes;
    private long _receiveOutstanding;
    private bool _responseHead;
    private bool _responseEnded;
    private int _closed;

    public HttpTunnelStream(TunnelConnectionContext context, uint streamId,
        Action<uint, HttpTunnelStream> onClose)
    {
        _context = context;
        StreamId = streamId;
        _onClose = onClose;
    }

    public uint StreamId { get; }

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
        }
        return Enqueue(new HttpStreamEvent(HttpStreamEventKind.Head, Clone(metadata), null, null));
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
            _receiveOutstanding += data.Length;
        }
        return Enqueue(new HttpStreamEvent(HttpStreamEventKind.Data, null, data.ToArray(), null));
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
        }
        return Enqueue(new HttpStreamEvent(HttpStreamEventKind.End, Clone(metadata), null, null));
    }

    public bool OnReset(string? reason)
    {
        var error = new IOException(string.IsNullOrWhiteSpace(reason)
            ? "HTTP stream reset by client"
            : reason);
        var written = Enqueue(new HttpStreamEvent(HttpStreamEventKind.Reset, null, null, error));
        Close();
        return written;
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
