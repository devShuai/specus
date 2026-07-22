namespace ShuaiTunnel.Protocol.Flow;

/// <summary>Per-stream outbound credit window for mandatory NAT stream v2.</summary>
public sealed class StreamSendWindow
{
    public const long InitialBytes = 1024L * 1024L;
    public const long MaximumBytes = 16L * 1024L * 1024L;

    private readonly object _sync = new();
    private readonly SemaphoreSlim _changed = new(0);
    private long _credit = InitialBytes;
    private long _outstanding;
    private bool _closed;

    public async ValueTask<bool> ConsumeAsync(int bytes, CancellationToken cancellationToken)
    {
        if (bytes <= 0 || bytes > MaximumBytes)
        {
            return false;
        }

        while (true)
        {
            lock (_sync)
            {
                if (_closed)
                {
                    return false;
                }
                if (_credit >= bytes)
                {
                    _credit -= bytes;
                    _outstanding += bytes;
                    return true;
                }
            }
            await _changed.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public bool Add(uint bytes)
    {
        if (bytes == 0 || bytes > MaximumBytes)
        {
            return false;
        }
        lock (_sync)
        {
            if (_closed || bytes > _outstanding || _credit > MaximumBytes - bytes)
            {
                return false;
            }
            _credit += bytes;
            _outstanding -= bytes;
        }
        _changed.Release();
        return true;
    }

    public void Close()
    {
        lock (_sync)
        {
            if (_closed)
            {
                return;
            }
            _closed = true;
        }
        _changed.Release();
    }
}
