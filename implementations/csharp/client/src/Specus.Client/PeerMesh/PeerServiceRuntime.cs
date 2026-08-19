using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Specus.Client.Configuration;

namespace Specus.Client.PeerMesh;

internal sealed class PeerServiceRuntime : IDisposable
{
    internal const int ProbeTimeoutMillis = 400;
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(15);
    private static readonly JsonSerializerOptions ReportJson = new(JsonSerializerDefaults.Web);

    private readonly Action<string> _send;
    private readonly ILogger? _logger;
    private readonly string _instanceId = Guid.NewGuid().ToString("N");
    private readonly object _sync = new();
    private readonly ConcurrentDictionary<CatalogKey, CatalogSnapshot> _catalogs = new();
    private readonly Dictionary<string, IPeerServiceForwarder> _bridges = new(StringComparer.Ordinal);
    private long _revision;
    private bool _hasAuthorizedOnlinePeer;
    private PeerMeshConfig _config = new();
    private Func<long, RosterHint>? _rosterLookup;
    private volatile Dictionary<long, RosterHint> _roster = new();
    private Timer? _probeTimer;
    private List<string> _lastReportedIds = [];
    private readonly HashSet<string> _locallyPaused = new(StringComparer.Ordinal);

    public PeerServiceRuntime(Action<string> send, ILogger? logger = null)
    {
        _send = send;
        _logger = logger;
    }

    public void SetRosterLookup(Func<long, RosterHint>? lookup)
    {
        _rosterLookup = lookup;
    }

    public void SetRoster(IReadOnlyDictionary<long, RosterHint> roster)
    {
        _roster = new Dictionary<long, RosterHint>(roster);
    }

    private RosterHint LookUpRoster(long clientId) =>
        _roster.TryGetValue(clientId, out var hint) ? hint : RosterHint.Unknown;

    public void ApplyConfig(PeerMeshConfig? next)
    {
        bool withdraw;
        lock (_sync)
        {
            _config = next ?? new PeerMeshConfig();
            if (!EffectiveSharing)
            {
                StopProbeLocked();
                CloseBridgesLocked();
                _catalogs.Clear();
                withdraw = _lastReportedIds.Count > 0 || _revision > 0;
            }
            else
            {
                ReconcileBridgesLocked();
                ScheduleProbeLocked();
                withdraw = false;
            }
        }
        if (withdraw)
        {
            SendWithdraw();
            return;
        }
        if (EffectiveSharing)
        {
            ProbeAndReport();
        }
    }

    public void SetHasAuthorizedOnlinePeer(bool onlinePeer)
    {
        bool changed;
        lock (_sync)
        {
            changed = _hasAuthorizedOnlinePeer != onlinePeer;
            _hasAuthorizedOnlinePeer = onlinePeer;
            if (!changed)
            {
                return;
            }
            if (!EffectiveSharing || !onlinePeer)
            {
                StopProbeLocked();
                CloseBridgesLocked();
                return;
            }
            ReconcileBridgesLocked();
            ScheduleProbeLocked();
        }
        ProbeAndReport();
    }

    public void ApplyCatalog(long publisherClientId, string? publisherClientName, long publisherSessionId,
        long revision, string? expiresAt, IReadOnlyList<AdvertisedService>? services)
    {
        if (publisherClientId <= 0 || publisherSessionId <= 0)
        {
            return;
        }
        var key = new CatalogKey(publisherClientId, publisherSessionId);
        var copy = (services ?? []).Select(CopyAdvertised).ToList();
        if (copy.Count == 0)
        {
            _catalogs.TryRemove(key, out _);
            _logger?.LogInformation("Peer 服务目录已撤回: publisher={Publisher} session={Session}",
                publisherClientName, publisherSessionId);
            return;
        }
        var expires = DateTimeOffset.UtcNow.Add(PeerServiceDiscovery.CatalogTtl);
        if (DateTimeOffset.TryParse(expiresAt, out var parsed))
        {
            expires = parsed;
        }
        _catalogs[key] = new CatalogSnapshot(publisherClientId, publisherClientName ?? "", publisherSessionId,
            revision, expires, copy);
        _logger?.LogInformation("Peer 服务目录已更新: publisher={Publisher} session={Session} services={Count}",
            publisherClientName, publisherSessionId, copy.Count);
        foreach (var view in RemoteServices())
        {
            _logger?.LogInformation("  {Publisher} {Application} {Target}",
                view.PublisherClientName, view.Service.Application, view.AccessTarget);
        }
    }

    public IReadOnlyList<RemoteServiceView> RemoteServices()
    {
        var now = DateTimeOffset.UtcNow;
        var views = new List<RemoteServiceView>();
        foreach (var snapshot in _catalogs.Values)
        {
            if (snapshot.ExpiresAt < now)
            {
                continue;
            }
            var hint = (_rosterLookup ?? LookUpRoster)(snapshot.PublisherClientId);
            foreach (var service in snapshot.Services)
            {
                views.Add(RemoteServiceView.From(snapshot, hint, service));
            }
        }
        return views;
    }

    public IReadOnlyList<LocalPeerService> LocalServices =>
        [.. _config.LocalServices ?? []];

    public bool IsLocallyPublished(string? serviceId) =>
        string.IsNullOrWhiteSpace(serviceId) || !_locallyPaused.Contains(serviceId);

    public void SetLocalPublished(string? serviceId, bool published)
    {
        if (string.IsNullOrWhiteSpace(serviceId))
        {
            return;
        }
        lock (_sync)
        {
            if (published)
            {
                _locallyPaused.Remove(serviceId);
            }
            else
            {
                _locallyPaused.Add(serviceId);
            }
        }
        ProbeAndReport();
    }

    public bool EffectiveSharing => _config.ServiceSharing?.EffectiveEnabled == true;

    internal void ProbeAndReport()
    {
        lock (_sync)
        {
            if (!EffectiveSharing || !_hasAuthorizedOnlinePeer)
            {
                CloseBridgesLocked();
                return;
            }
            var reachable = new List<AdvertisedService>();
            foreach (var local in EnabledLocalsLocked())
            {
                if (!PeerServiceDiscovery.Probe(local, ProbeTimeoutMillis))
                {
                    continue;
                }
                reachable.Add(AdvertisedFrom(local));
            }
            var ids = reachable.Select(item => item.ServiceId).ToList();
            if (ids.SequenceEqual(_lastReportedIds) && _revision > 0)
            {
                ReconcileBridgesLocked();
                return;
            }
            _lastReportedIds = ids;
            SendReportLocked(true, reachable);
            ReconcileBridgesLocked();
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            StopProbeLocked();
            CloseBridgesLocked();
            _catalogs.Clear();
        }
    }

    private void ReconcileBridgesLocked()
    {
        if (!EffectiveSharing || !_hasAuthorizedOnlinePeer || string.IsNullOrWhiteSpace(_config.VirtualIp))
        {
            CloseBridgesLocked();
            return;
        }
        var desired = new Dictionary<string, LocalPeerService>(StringComparer.Ordinal);
        foreach (var local in EnabledLocalsLocked())
        {
            if (PeerServiceDiscovery.Probe(local, ProbeTimeoutMillis))
            {
                desired[local.ServiceId] = local;
            }
        }
        foreach (var id in _bridges.Keys.ToList())
        {
            if (!desired.ContainsKey(id))
            {
                _bridges.Remove(id, out var removed);
                removed?.Dispose();
            }
        }
        foreach (var local in desired.Values)
        {
            if (_bridges.TryGetValue(local.ServiceId, out var current) && current.Matches(_config.VirtualIp!, local))
            {
                continue;
            }
            if (_bridges.Remove(local.ServiceId, out var previous))
            {
                previous.Dispose();
            }
            try
            {
                _bridges[local.ServiceId] = BindForwarder(_config.VirtualIp!, local, _logger);
                _logger?.LogInformation("Peer-only 桥接已监听 {Bind} -> {Target}:{Port}",
                    $"{_config.VirtualIp}:{local.PublishedPort}", local.TargetHost, local.TargetPort);
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Peer-only 桥接暂不可用 service={ServiceId}", local.ServiceId);
            }
        }
    }

    private List<LocalPeerService> EnabledLocalsLocked() =>
        (_config.LocalServices ?? [])
            .Where(item => item is { Enabled: true } && !_locallyPaused.Contains(item.ServiceId))
            .ToList();

    private void ScheduleProbeLocked()
    {
        StopProbeLocked();
        _probeTimer = new Timer(_ =>
        {
            try
            {
                ProbeAndReport();
            }
            catch
            {
                // next tick retries
            }
        }, null, ProbeInterval, ProbeInterval);
    }

    private void StopProbeLocked()
    {
        _probeTimer?.Dispose();
        _probeTimer = null;
    }

    private void SendWithdraw()
    {
        lock (_sync)
        {
            _lastReportedIds = [];
            SendReportLocked(false, []);
        }
    }

    private void SendReportLocked(bool enabled, List<AdvertisedService> services)
    {
        var report = new ServiceReportMessage
        {
            Type = "service-report",
            Enabled = enabled,
            Revision = Interlocked.Increment(ref _revision),
            InstanceId = _instanceId,
            GeneratedAt = DateTimeOffset.UtcNow.ToString("O"),
            ExpiresAt = DateTimeOffset.UtcNow.Add(PeerServiceDiscovery.CatalogTtl).ToString("O"),
            Services = services,
            Stats = _bridges.Values.Select(item =>
            {
                var snapshot = item.Snapshot();
                return new PeerServiceStatsDto
                {
                    ServiceId = item.ServiceId,
                    BytesIn = snapshot.BytesIn,
                    BytesOut = snapshot.BytesOut,
                    ActiveConnections = snapshot.Active,
                    TotalConnections = snapshot.Total,
                };
            }).ToList(),
            MdnsCandidates = _config.ServiceSharing?.MdnsImportEnabled == true
                ? PeerMdnsBrowser.Browse(TimeSpan.FromMilliseconds(ProbeTimeoutMillis)).ToList()
                : [],
            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        _send(JsonSerializer.Serialize(report, ReportJson));
    }

    private static IPeerServiceForwarder BindForwarder(string virtualIp, LocalPeerService local, ILogger? logger)
    {
        if (string.Equals(local.Transport, "udp", StringComparison.OrdinalIgnoreCase)
            || string.Equals(local.Application, "udp", StringComparison.OrdinalIgnoreCase))
        {
            return PeerServiceUdpBridge.Bind(virtualIp, local, logger);
        }
        return PeerServiceBridge.Bind(virtualIp, local, logger);
    }

    private void CloseBridgesLocked()
    {
        foreach (var bridge in _bridges.Values)
        {
            bridge.Dispose();
        }
        _bridges.Clear();
    }

    private static AdvertisedService AdvertisedFrom(LocalPeerService local) => new()
    {
        ServiceId = local.ServiceId,
        Name = local.Name,
        Description = local.Description,
        Transport = local.Transport,
        Application = local.Application,
        PublishedPort = local.PublishedPort,
        Path = local.Path,
    };

    private static AdvertisedService CopyAdvertised(AdvertisedService source) => new()
    {
        ServiceId = source.ServiceId,
        Name = source.Name,
        Description = source.Description,
        Transport = source.Transport,
        Application = source.Application,
        PublishedPort = source.PublishedPort,
        Path = source.Path,
    };

    internal readonly record struct RosterHint(string VirtualIp, bool Online)
    {
        public static RosterHint Unknown => new("", false);
    }

    private readonly record struct CatalogKey(long PublisherClientId, long PublisherSessionId);

    internal sealed record CatalogSnapshot(
        long PublisherClientId,
        string PublisherClientName,
        long PublisherSessionId,
        long Revision,
        DateTimeOffset ExpiresAt,
        List<AdvertisedService> Services);

    internal sealed record RemoteServiceView(
        long PublisherClientId,
        string PublisherClientName,
        long PublisherSessionId,
        string VirtualIp,
        bool PublisherOnline,
        bool Fresh,
        AdvertisedService Service,
        string AccessTarget,
        bool Openable,
        bool Copyable,
        string UnavailableReason)
    {
        internal static RemoteServiceView From(CatalogSnapshot snapshot, RosterHint hint, AdvertisedService service)
        {
            var http = service.Application is "http" or "https";
            var fresh = snapshot.ExpiresAt > DateTimeOffset.UtcNow;
            var virtualIp = hint.VirtualIp ?? "";
            var reason = !fresh ? "目录已过期"
                : !hint.Online ? "发布端离线"
                : string.IsNullOrWhiteSpace(virtualIp) ? "缺少虚拟 IP"
                : "";
            return new RemoteServiceView(
                snapshot.PublisherClientId,
                snapshot.PublisherClientName,
                snapshot.PublisherSessionId,
                virtualIp,
                hint.Online,
                fresh,
                service,
                string.IsNullOrWhiteSpace(virtualIp) ? "" : PeerServiceDiscovery.AccessUrl(virtualIp, service),
                http && reason.Length == 0,
                !http && reason.Length == 0,
                reason);
        }
    }

    private sealed class ServiceReportMessage
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "";
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; }
        [JsonPropertyName("revision")]
        public long Revision { get; set; }
        [JsonPropertyName("instanceId")]
        public string InstanceId { get; set; } = "";
        [JsonPropertyName("generatedAt")]
        public string GeneratedAt { get; set; } = "";
        [JsonPropertyName("expiresAt")]
        public string ExpiresAt { get; set; } = "";
        [JsonPropertyName("services")]
        public List<AdvertisedService> Services { get; set; } = [];
        [JsonPropertyName("createdAtMillis")]
        public long CreatedAtMillis { get; set; }
        [JsonPropertyName("stats")]
        public List<PeerServiceStatsDto> Stats { get; set; } = [];
        [JsonPropertyName("mdnsCandidates")]
        public List<PeerMdnsCandidate> MdnsCandidates { get; set; } = [];
    }

    private sealed class PeerServiceStatsDto
    {
        [JsonPropertyName("serviceId")]
        public string ServiceId { get; set; } = "";
        [JsonPropertyName("bytesIn")]
        public long BytesIn { get; set; }
        [JsonPropertyName("bytesOut")]
        public long BytesOut { get; set; }
        [JsonPropertyName("activeConnections")]
        public int ActiveConnections { get; set; }
        [JsonPropertyName("totalConnections")]
        public long TotalConnections { get; set; }
    }
}
