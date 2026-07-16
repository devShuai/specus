using System.Diagnostics;
using System.Net;

namespace ShuaiTunnel.StunServer;

public enum StunLimitDecision
{
    Allowed,
    GlobalRateLimit,
    SourceRateLimit,
    SourceTableFull,
}

public sealed class StunRequestLimiter
{
    private const long CleanupMask = 1_023;

    private readonly object _sync = new();
    private readonly StunProtectionConfig _config;
    private readonly TokenBucket _global;
    private readonly Dictionary<string, SourceBucket> _sources = new(StringComparer.Ordinal);
    private long _requestCount;

    public StunRequestLimiter(StunProtectionConfig config)
    {
        _config = config;
        var now = Stopwatch.GetTimestamp();
        _global = new TokenBucket(config.GlobalBurst, now);
    }

    public StunLimitDecision Allow(IPAddress source)
    {
        lock (_sync)
        {
            var now = Stopwatch.GetTimestamp();
            _requestCount++;
            if (!_global.TryConsume(now, _config.GlobalRatePerSecond, _config.GlobalBurst))
            {
                return StunLimitDecision.GlobalRateLimit;
            }
            if ((_requestCount & CleanupMask) == 0)
            {
                RemoveIdle(now);
            }
            var key = source.ToString();
            if (!_sources.TryGetValue(key, out var bucket))
            {
                if (_sources.Count >= _config.MaxTrackedSources)
                {
                    RemoveIdle(now);
                }
                if (_sources.Count >= _config.MaxTrackedSources)
                {
                    return StunLimitDecision.SourceTableFull;
                }
                bucket = new SourceBucket(
                    new TokenBucket(_config.SourceBurst, now),
                    now);
                _sources.Add(key, bucket);
            }
            bucket.LastSeenTicks = now;
            return bucket.Tokens.TryConsume(now, _config.SourceRatePerSecond, _config.SourceBurst)
                ? StunLimitDecision.Allowed
                : StunLimitDecision.SourceRateLimit;
        }
    }

    public int TrackedSources()
    {
        lock (_sync)
        {
            RemoveIdle(Stopwatch.GetTimestamp());
            return _sources.Count;
        }
    }

    private void RemoveIdle(long now)
    {
        var idleTicks = (long)(_config.SourceIdleSeconds * (double)Stopwatch.Frequency);
        foreach (var key in _sources
                     .Where(item => now - item.Value.LastSeenTicks >= idleTicks)
                     .Select(item => item.Key)
                     .ToList())
        {
            _sources.Remove(key);
        }
    }

    private sealed class SourceBucket(TokenBucket tokens, long lastSeenTicks)
    {
        public TokenBucket Tokens { get; } = tokens;
        public long LastSeenTicks { get; set; } = lastSeenTicks;
    }

    private sealed class TokenBucket(double tokens, long updatedTicks)
    {
        private double _tokens = tokens;
        private long _updatedTicks = updatedTicks;

        public bool TryConsume(long now, int ratePerSecond, int burst)
        {
            var elapsed = Math.Max(0, now - _updatedTicks);
            if (elapsed > 0)
            {
                _tokens = Math.Min(
                    burst,
                    _tokens + elapsed * (double)ratePerSecond / Stopwatch.Frequency);
                _updatedTicks = now;
            }
            if (_tokens < 1D)
            {
                return false;
            }
            _tokens -= 1D;
            return true;
        }
    }
}
