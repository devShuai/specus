using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;

namespace ShuaiTunnel.Client.DirectHttp;

/// <summary>
/// Holds the HTTP route snapshot used by mandatory NAT stream v2 exchanges.
/// </summary>
internal sealed class DirectHttpHandler
{
    private volatile IReadOnlyDictionary<string, string> _routes;

    public DirectHttpHandler(
        IEnumerable<HttpTunnelConfigEntry>? initialRoutes,
        FrameWriter writer,
        DirectHttpForwarder forwarder,
        ILogger logger)
    {
        Forwarder = forwarder;
        _ = writer;
        _ = logger;
        _routes = BuildMap(initialRoutes);
    }

    public DirectHttpForwarder Forwarder { get; }

    public IReadOnlyDictionary<string, string> SnapshotRoutes() => _routes;

    /// <summary>
    /// Replaces the route map with a server-pushed snapshot. A <c>null</c> argument keeps the
    /// current local fallback (matching the Java handler's "未接管" semantics).
    /// </summary>
    public void ApplyRoutes(IEnumerable<HttpTunnelConfigEntry>? next)
    {
        if (next is null)
        {
            return;
        }
        _routes = BuildMap(next);
    }

    private static IReadOnlyDictionary<string, string> BuildMap(IEnumerable<HttpTunnelConfigEntry>? source)
    {
        if (source is null)
        {
            return new Dictionary<string, string>();
        }
        var map = new Dictionary<string, string>();
        foreach (var entry in source)
        {
            if (string.IsNullOrWhiteSpace(entry.Route))
            {
                continue;
            }
            map[entry.Route] = entry.TargetBaseUrl;
        }
        return map;
    }
}
