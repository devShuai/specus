namespace ShuaiTunnel.Server.Data.Entities;

/// <summary>
/// Mirrors <c>tunnel_mapping</c> — a TCP tunnel a client has registered. Phase 3 is what
/// actually consumes this; Phase 2 just lays the table down so migrations stay in lockstep.
/// </summary>
public sealed class TunnelMapping
{
    public long Id { get; set; }
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public int ListenPort { get; set; }
    public string TargetAddress { get; set; } = string.Empty;
    public int TargetPort { get; set; }
    public bool Enabled { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Mirrors <c>http_route_mapping</c> — Phase 4 surface.</summary>
public sealed class HttpRouteMapping
{
    public long Id { get; set; }
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string Route { get; set; } = string.Empty;
    public string TargetBaseUrl { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Mirrors <c>tunnel_traffic_usage</c> — daily up/down byte tallies.</summary>
public sealed class TrafficUsage
{
    public long Id { get; set; }
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;

    /// <summary>UTC date in <c>yyyy-MM-dd</c> form — TEXT column for Java compat.</summary>
    public string UsageDate { get; set; } = string.Empty;

    public long UploadBytes { get; set; }
    public long DownloadBytes { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Mirrors <c>tunnel_connection_stat</c> — monthly archive aggregations.</summary>
public sealed class ConnectionStat
{
    public long Id { get; set; }
    public long? ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;

    /// <summary>UTC month in <c>yyyy-MM</c> form.</summary>
    public string StatMonth { get; set; } = string.Empty;

    public long TotalCount { get; set; }
    public long SuccessCount { get; set; }
    public long FailureCount { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
