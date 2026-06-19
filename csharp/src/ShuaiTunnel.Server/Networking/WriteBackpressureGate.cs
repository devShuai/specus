namespace ShuaiTunnel.Server.Networking;

/// <summary>
/// Tracks queued outbound bytes and exposes a Netty-style writable signal using high/low water
/// marks. Callers add bytes before entering a serialized write and release them after the write
/// completes, so queued writers count toward backpressure too.
/// </summary>
public sealed class WriteBackpressureGate
{
    private long _pendingBytes;
    private int _isBackpressured;

    public WriteBackpressureGate(long lowWaterMark, long highWaterMark)
    {
        LowWaterMark = Math.Max(0, lowWaterMark);
        HighWaterMark = Math.Max(LowWaterMark + 1, highWaterMark);
    }

    public event Action<bool>? BackpressureChanged;

    public long LowWaterMark { get; }

    public long HighWaterMark { get; }

    public long PendingBytes => Math.Max(0, Volatile.Read(ref _pendingBytes));

    public bool IsBackpressured => Volatile.Read(ref _isBackpressured) == 1;

    public long AddPending(long bytes)
    {
        if (bytes <= 0)
        {
            return 0;
        }

        var pending = Interlocked.Add(ref _pendingBytes, bytes);
        if (pending >= HighWaterMark && Interlocked.Exchange(ref _isBackpressured, 1) == 0)
        {
            Notify(backpressured: true);
        }
        return bytes;
    }

    public void ReleasePending(long bytes)
    {
        if (bytes <= 0)
        {
            return;
        }

        var pending = Interlocked.Add(ref _pendingBytes, -bytes);
        if (pending < 0)
        {
            Interlocked.Add(ref _pendingBytes, -pending);
            pending = 0;
        }

        if (pending <= LowWaterMark && Interlocked.Exchange(ref _isBackpressured, 0) == 1)
        {
            Notify(backpressured: false);
        }
    }

    private void Notify(bool backpressured)
    {
        var handlers = BackpressureChanged;
        if (handlers is null)
        {
            return;
        }

        foreach (var handler in handlers.GetInvocationList())
        {
            try
            {
                ((Action<bool>)handler)(backpressured);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"write backpressure callback failed: {ex.Message}");
            }
        }
    }
}
