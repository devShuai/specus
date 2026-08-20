using System.Net;

namespace Specus.Client.PeerMesh;

internal static class PeerServiceResourceLimiter
{
    internal const int MaxTcpGlobal = 256;
    internal const int MaxTcpPerService = 64;
    internal const int MaxTcpPerSource = 8;
    internal const int MaxUdpGlobal = 256;
    internal const int MaxUdpPerService = 64;
    internal const int MaxUdpPerSource = 8;
    internal static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);
    internal static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(60);

    private static readonly object Gate = new();
    private static readonly SemaphoreSlim TcpGlobal = new(MaxTcpGlobal, MaxTcpGlobal);
    private static readonly SemaphoreSlim UdpGlobal = new(MaxUdpGlobal, MaxUdpGlobal);
    private static readonly Dictionary<IPAddress, int> TcpSources = [];
    private static readonly Dictionary<IPAddress, int> UdpSources = [];

    internal static Lease? TryAcquireTcp(IPAddress source) =>
        TryAcquire(source, TcpGlobal, TcpSources, MaxTcpPerSource);

    internal static Lease? TryAcquireUdp(IPAddress source) =>
        TryAcquire(source, UdpGlobal, UdpSources, MaxUdpPerSource);

    private static Lease? TryAcquire(IPAddress source, SemaphoreSlim global,
        Dictionary<IPAddress, int> sources, int sourceLimit)
    {
        source = Normalize(source);
        if (!global.Wait(0))
        {
            return null;
        }
        lock (Gate)
        {
            sources.TryGetValue(source, out var active);
            if (active >= sourceLimit)
            {
                global.Release();
                return null;
            }
            sources[source] = active + 1;
        }
        return new Lease(source, global, sources);
    }

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    internal sealed class Lease(IPAddress source, SemaphoreSlim global, Dictionary<IPAddress, int> sources)
        : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }
            lock (Gate)
            {
                var remaining = sources.GetValueOrDefault(source) - 1;
                if (remaining <= 0)
                {
                    sources.Remove(source);
                }
                else
                {
                    sources[source] = remaining;
                }
            }
            global.Release();
        }
    }
}
