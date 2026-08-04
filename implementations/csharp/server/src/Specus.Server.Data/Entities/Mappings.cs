namespace Specus.Server.Data.Entities;

/// <summary>
/// Mirrors <c>specus_mapping</c> — a TCP specus a client has registered. Phase 3 is what
/// actually consumes this; Phase 2 just lays the table down so migrations stay in lockstep.
/// </summary>
public sealed class SpecusMapping
{
    public long Id { get; set; }
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public int ListenPort { get; set; }
    public string TargetAddress { get; set; } = string.Empty;
    public int TargetPort { get; set; }
    public bool Enabled { get; set; }
    public bool DetailCaptureEnabled { get; set; }
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
    public bool DetailCaptureEnabled { get; set; }
    public bool PathRewriteEnabled { get; set; }
    public bool AuthEnabled { get; set; }
    public string? AuthUsername { get; set; }
    public string? AuthPasswordHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Mirrors <c>specus_traffic_usage</c> — daily up/down byte tallies.</summary>
public sealed class TrafficUsage
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;

    /// <summary>UTC date in <c>yyyy-MM-dd</c> form — TEXT column for Java compat.</summary>
    public string UsageDate { get; set; } = string.Empty;

    public long UploadBytes { get; set; }
    public long DownloadBytes { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Mirrors <c>specus_resource_traffic_usage</c> — daily per TCP/HTTP resource tallies.</summary>
public sealed class ResourceTrafficUsage
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string ResourceType { get; set; } = string.Empty;
    public string ResourceKey { get; set; } = string.Empty;
    public long? ResourceId { get; set; }
    public string ResourceName { get; set; } = string.Empty;
    public string UsageDate { get; set; } = string.Empty;
    public long UploadBytes { get; set; }
    public long DownloadBytes { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Mirrors <c>specus_http_traffic_exchange</c> — detailed HTTP route observation.</summary>
public sealed class HttpTrafficExchange
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string Route { get; set; } = string.Empty;
    public long? ResourceId { get; set; }
    public string? ResourceName { get; set; }
    public string Method { get; set; } = string.Empty;
    public string RelativePath { get; set; } = "/";
    public string? RawQuery { get; set; }
    public int StatusCode { get; set; }
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string? RemoteAddress { get; set; }
    public long RequestBytes { get; set; }
    public long ResponseBytes { get; set; }
    public long ElapsedMs { get; set; }
    public string? RequestContentType { get; set; }
    public string? ResponseContentType { get; set; }
    public string ResponseBodyType { get; set; } = "empty";
    public string? RequestHeaders { get; set; }
    public string? ResponseHeaders { get; set; }
    public string? RequestPreviewHex { get; set; }
    public string? RequestPreviewText { get; set; }
    public string? ResponsePreviewHex { get; set; }
    public string? ResponsePreviewText { get; set; }
    public bool RequestTruncated { get; set; }
    public bool ResponseTruncated { get; set; }
    public DateTimeOffset CapturedAt { get; set; }
}

/// <summary>Mirrors <c>specus_tcp_traffic_frame</c> — detailed TCP frame observation.</summary>
public sealed class TcpTrafficFrame
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public int ListenPort { get; set; }
    public long? ResourceId { get; set; }
    public string? ResourceName { get; set; }
    public string ChannelId { get; set; } = string.Empty;
    public string Direction { get; set; } = string.Empty;
    public string? RemoteAddress { get; set; }
    public string? SourceAddress { get; set; }
    public int? SourcePort { get; set; }
    public string? DestinationAddress { get; set; }
    public int? DestinationPort { get; set; }
    public long StreamOffset { get; set; }
    public long StreamEndOffset { get; set; }
    public long FrameIndex { get; set; }
    public long PayloadBytes { get; set; }
    public byte[] PayloadData { get; set; } = [];
    public string? PayloadPreviewHex { get; set; }
    public string? PayloadPreviewText { get; set; }
    public bool Truncated { get; set; }
    public DateTimeOffset FrameTime { get; set; }
}

/// <summary>Mirrors <c>specus_connection_stat</c> — monthly archive aggregations.</summary>
public sealed class ConnectionStat
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long? ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;

    /// <summary>UTC month in <c>yyyy-MM</c> form.</summary>
    public string StatMonth { get; set; } = string.Empty;

    public long TotalCount { get; set; }
    public long SuccessCount { get; set; }
    public long FailureCount { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Mirrors <c>client_download_link</c> — public/admin downloadable client package metadata.</summary>
public sealed class ClientDownloadLink
{
    public long Id { get; set; }
    public string Implementation { get; set; } = string.Empty;
    public string Platform { get; set; } = string.Empty;
    public string Arch { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string DownloadUrl { get; set; } = string.Empty;
    public string? Description { get; set; }
    public int DisplayOrder { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
