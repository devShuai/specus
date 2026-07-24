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
    private readonly ILogger _logger;

    public DirectHttpHandler(
        IEnumerable<HttpTunnelConfigEntry>? initialRoutes,
        FrameWriter writer,
        DirectHttpForwarder forwarder,
        ILogger logger)
    {
        Forwarder = forwarder;
        _ = writer;
        _logger = logger;
        _routes = BuildMap(initialRoutes);
        LogSnapshot("initialized", _routes);
    }

    public DirectHttpForwarder Forwarder { get; }

    public IReadOnlyDictionary<string, string> SnapshotRoutes() => _routes;

    public bool TryResolveRoute(string route, out string targetBaseUrl) =>
        _routes.TryGetValue(route, out targetBaseUrl!);

    public string DescribeRoutes() =>
        string.Join(", ", _routes.Keys.Order(StringComparer.Ordinal));

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
        var routes = BuildMap(next);
        _routes = routes;
        LogSnapshot("applied", routes);
    }

    private static IReadOnlyDictionary<string, string> BuildMap(IEnumerable<HttpTunnelConfigEntry>? source)
    {
        if (source is null)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in source)
        {
            if (string.IsNullOrWhiteSpace(entry.Route))
            {
                continue;
            }
            map[entry.Route.Trim()] = entry.TargetBaseUrl;
        }
        return map;
    }

    private void LogSnapshot(string action, IReadOnlyDictionary<string, string> routes)
    {
        _logger.LogInformation(
            "HTTP route snapshot {Action}: count={Count}, routes=[{Routes}]",
            action,
            routes.Count,
            string.Join(", ", routes.Keys.Order(StringComparer.Ordinal)));
    }
}
