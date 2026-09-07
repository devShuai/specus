using System.Diagnostics;

namespace Specus.Client.Runtime;

/// <summary>Coalesces network hints; it never owns or starts a client.</summary>
public sealed class ReconnectWakeup
{
    private readonly SemaphoreSlim _signal = new(0, 1);
    private readonly object _gate = new();
    private long? _lastRequest;

    public bool Request()
    {
        lock (_gate)
        {
            var now = Stopwatch.GetTimestamp();
            if (_lastRequest is { } last && Stopwatch.GetElapsedTime(last, now) < TimeSpan.FromSeconds(2))
                return false;
            _lastRequest = now;
            if (_signal.CurrentCount == 0) _signal.Release();
            return true;
        }
    }

    public async Task WaitAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        await _signal.WaitAsync(delay, cancellationToken).ConfigureAwait(false);

    public static int DelaySeconds(int attempt, double jitter)
    {
        int ceiling = Math.Min(2 * (1 << Math.Clamp(attempt - 1, 0, 5)), 60);
        return Math.Max(1, (int)Math.Ceiling(ceiling * (0.75 + 0.25 * Math.Clamp(jitter, 0, 1))));
    }
}
