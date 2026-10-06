namespace Specus.Server.Http;

/// <summary>
/// Generic cell rate algorithm, identical to the share vectors and the connectivity-check draft:
/// one theoretical arrival time (TAT, integer ms) per key. A request at <c>now</c> conforms when
/// <c>now &gt;= TAT - tolerance</c>; conforming moves TAT to <c>max(TAT, now) + interval</c>, a
/// refusal consumes nothing. <c>tolerance = (burst - 1) * interval</c>. State is per process, like
/// every other limiter of this server.
/// </summary>
public class GcraRateLimiter
{
    public const int DefaultMaxKeys = 10_000;

    private readonly object _sync = new();
    private readonly Dictionary<string, long> _tat = new(StringComparer.Ordinal);
    private readonly long _interval;
    private readonly long _tolerance;
    private readonly int _maxKeys;

    public GcraRateLimiter(long intervalMs, int burst, int maxKeys = DefaultMaxKeys)
    {
        _interval = intervalMs;
        _tolerance = (burst - 1) * intervalMs;
        _maxKeys = maxKeys;
    }

    /// <summary>
    /// Admits one request for <paramref name="key"/> at <paramref name="nowMs"/>, or reports how
    /// long to wait. A full key table first drops entries whose TAT is not after now; when every
    /// entry is still live a new key is refused rather than evicting one.
    /// </summary>
    public bool TryAcquire(string key, long nowMs, out long waitMs)
    {
        lock (_sync)
        {
            if (!_tat.TryGetValue(key, out var tat))
            {
                if (_tat.Count >= _maxKeys)
                {
                    foreach (var stale in _tat.Where(entry => entry.Value <= nowMs).Select(entry => entry.Key)
                                 .ToList())
                    {
                        _tat.Remove(stale);
                    }
                    if (_tat.Count >= _maxKeys)
                    {
                        waitMs = 1000;
                        return false;
                    }
                }
                tat = nowMs;
            }
            waitMs = Math.Max(0, tat - _tolerance - nowMs);
            if (waitMs > 0)
            {
                return false;
            }
            _tat[key] = Math.Max(tat, nowMs) + _interval;
            return true;
        }
    }

    /// <summary>Forgets every key; lets tests replay independent cases against one instance.</summary>
    internal void Reset()
    {
        lock (_sync)
        {
            _tat.Clear();
        }
    }

    /// <summary>Retry-After for a refusal: the wait rounded up to whole seconds, at least 1.</summary>
    public static long RetryAfterSeconds(long waitMs) => Math.Max(1, (waitMs + 999) / 1000);
}

/// <summary>Exchange limiter: per source address (resolved through trusted proxies), 10 then 1/6 s.</summary>
public sealed class HttpShareExchangeRateLimiter()
    : GcraRateLimiter(HttpShareProtocol.ExchangeIntervalMs, HttpShareProtocol.ExchangeBurst);

/// <summary>Share request limiter: per share id, 200 at once then 20 per second.</summary>
public sealed class HttpShareRequestRateLimiter()
    : GcraRateLimiter(HttpShareProtocol.ShareIntervalMs, HttpShareProtocol.ShareBurst);
