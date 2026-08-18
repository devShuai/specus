using System.Net;

namespace Specus.Client.PeerMesh;

/// <summary>Fixed-window probe limiter aligned with the Java client.</summary>
internal sealed class PeerUdpProbeRateLimiter
{
    internal const long WindowMilliseconds = 1_000;
    internal const long SourceTtlMilliseconds = 60_000;
    internal const int GlobalPacketsPerWindow = 2_000;
    internal const int SourcePacketsPerWindow = 100;
    internal const int MaxSources = 4_096;

    private readonly object _gate = new();
    private readonly Dictionary<IPAddress, SourceWindow> _sourceWindows = [];
    private long _globalWindowStartedMilliseconds;
    private int _globalPackets;

    internal int SourceCount
    {
        get
        {
            lock (_gate)
            {
                return _sourceWindows.Count;
            }
        }
    }

    internal bool TryAcquire(IPAddress? source, long nowMilliseconds)
    {
        lock (_gate)
        {
            if (nowMilliseconds - _globalWindowStartedMilliseconds >= WindowMilliseconds)
            {
                _globalWindowStartedMilliseconds = nowMilliseconds;
                _globalPackets = 0;
            }
            if (++_globalPackets > GlobalPacketsPerWindow || source is null)
            {
                return false;
            }

            source = Normalize(source);
            if (!_sourceWindows.TryGetValue(source, out var window))
            {
                EvictIfNeeded(nowMilliseconds);
                window = new SourceWindow(nowMilliseconds, 0, nowMilliseconds);
                _sourceWindows[source] = window;
            }
            if (nowMilliseconds - window.StartedMilliseconds >= WindowMilliseconds)
            {
                window.StartedMilliseconds = nowMilliseconds;
                window.Packets = 0;
            }
            window.LastSeenMilliseconds = nowMilliseconds;
            return ++window.Packets <= SourcePacketsPerWindow;
        }
    }

    internal void Cleanup(long nowMilliseconds)
    {
        lock (_gate)
        {
            foreach (var source in _sourceWindows
                         .Where(pair => nowMilliseconds - pair.Value.LastSeenMilliseconds > SourceTtlMilliseconds)
                         .Select(pair => pair.Key)
                         .ToList())
            {
                _sourceWindows.Remove(source);
            }
        }
    }

    private void EvictIfNeeded(long nowMilliseconds)
    {
        CleanupLocked(nowMilliseconds);
        while (_sourceWindows.Count >= MaxSources)
        {
            var oldest = _sourceWindows.MinBy(pair => pair.Value.LastSeenMilliseconds);
            _sourceWindows.Remove(oldest.Key);
        }
    }

    private void CleanupLocked(long nowMilliseconds)
    {
        foreach (var source in _sourceWindows
                     .Where(pair => nowMilliseconds - pair.Value.LastSeenMilliseconds > SourceTtlMilliseconds)
                     .Select(pair => pair.Key)
                     .ToList())
        {
            _sourceWindows.Remove(source);
        }
    }

    private static IPAddress Normalize(IPAddress source)
        => source.IsIPv4MappedToIPv6 ? source.MapToIPv4() : source;

    private sealed class SourceWindow(
        long startedMilliseconds,
        int packets,
        long lastSeenMilliseconds)
    {
        public long StartedMilliseconds { get; set; } = startedMilliseconds;

        public int Packets { get; set; } = packets;

        public long LastSeenMilliseconds { get; set; } = lastSeenMilliseconds;
    }
}
