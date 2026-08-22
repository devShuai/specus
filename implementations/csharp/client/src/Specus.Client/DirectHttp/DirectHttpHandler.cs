using Microsoft.Extensions.Logging;
using Specus.Client.Configuration;
using Specus.Client.Control;

namespace Specus.Client.DirectHttp;

/// <summary>
/// Holds the HTTP route snapshot used by mandatory NAT stream v2 exchanges.
/// </summary>
internal sealed class DirectHttpHandler
{
    private volatile IReadOnlyDictionary<string, HttpSpecusConfigEntry> _routes;
    private readonly ILogger _logger;

    public DirectHttpHandler(
        IEnumerable<HttpSpecusConfigEntry>? initialRoutes,
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

    public IReadOnlyDictionary<string, string> SnapshotRoutes() =>
        _routes.ToDictionary(static pair => pair.Key, static pair => pair.Value.TargetBaseUrl,
            StringComparer.Ordinal);

    public bool TryResolveRoute(string route, out string targetBaseUrl)
    {
        if (TryResolveRouteConfig(route, out var config))
        {
            targetBaseUrl = config.TargetBaseUrl;
            return true;
        }
        targetBaseUrl = string.Empty;
        return false;
    }

    public bool TryResolveRouteConfig(string route, out HttpSpecusConfigEntry config) =>
        _routes.TryGetValue(route, out config!);

    public string DescribeRoutes() =>
        string.Join(", ", _routes.Keys.Order(StringComparer.Ordinal));

    /// <summary>
    /// Replaces the route map with a server-pushed snapshot. A <c>null</c> argument keeps the
    /// current local fallback (matching the Java handler's "未接管" semantics).
    /// </summary>
    public void ApplyRoutes(IEnumerable<HttpSpecusConfigEntry>? next)
    {
        if (next is null)
        {
            return;
        }
        var routes = BuildMap(next);
        _routes = routes;
        LogSnapshot("applied", routes);
    }

    private static IReadOnlyDictionary<string, HttpSpecusConfigEntry> BuildMap(
        IEnumerable<HttpSpecusConfigEntry>? source)
    {
        if (source is null)
        {
            return new Dictionary<string, HttpSpecusConfigEntry>(StringComparer.Ordinal);
        }
        var map = new Dictionary<string, HttpSpecusConfigEntry>(StringComparer.Ordinal);
        foreach (var entry in source)
        {
            if (string.IsNullOrWhiteSpace(entry.Route))
            {
                continue;
            }
            var route = entry.Route.Trim();
            map[route] = new HttpSpecusConfigEntry
            {
                Route = route,
                TargetBaseUrl = entry.TargetBaseUrl,
                InsecureSkipVerify = entry.InsecureSkipVerify,
            };
        }
        return map;
    }

    private void LogSnapshot(
        string action, IReadOnlyDictionary<string, HttpSpecusConfigEntry> routes)
    {
        _logger.LogInformation(
            "HTTP route snapshot {Action}: count={Count}, routes=[{Routes}]",
            action,
            routes.Count,
            string.Join(", ", routes.Keys.Order(StringComparer.Ordinal)));
    }
}
