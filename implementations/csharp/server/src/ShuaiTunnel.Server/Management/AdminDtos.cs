namespace ShuaiTunnel.Server.Management;

public sealed record AdminLoginRequest(string? Username, string? Password);

public sealed record ManagementUserView(
    string Username,
    string TenantId,
    string Role,
    bool Admin,
    bool BuiltIn,
    bool Enabled,
    string CreatedAt,
    string UpdatedAt);

public sealed record UserMutation(
    string? Username,
    string? Password,
    string? Role,
    bool? Enabled);

public sealed record ClientMutation(
    string? ClientName,
    bool? Enabled,
    int? ConnectionRateLimitPerMinute);

public sealed record ClientResult(ClientAccountView Client);

public sealed record CredentialMutation(
    string? ApiKey,
    string? Secret,
    bool? Enabled,
    int? MaxOnlineInstances);

public sealed record CredentialResult(ClientCredentialView Credential, string? Secret);

public sealed record ClientCredentialView(
    long Id,
    string ApiKey,
    string? OwnerUsername,
    bool Enabled,
    int MaxOnlineInstances,
    string CreatedAt,
    string UpdatedAt);

public sealed record ClientDownloadLinkView(
    long Id,
    string Implementation,
    string Platform,
    string Arch,
    string DisplayName,
    string DownloadUrl,
    string? Description,
    int DisplayOrder,
    bool Enabled,
    string CreatedAt,
    string UpdatedAt);

public sealed record ClientDownloadLinkMutation(
    string? Implementation,
    string? Platform,
    string? Arch,
    string? DisplayName,
    string? DownloadUrl,
    string? Description,
    int? DisplayOrder,
    bool? Enabled);

public sealed record ClientAccountView(
    long Id,
    string ClientName,
    string? OwnerUsername,
    bool Enabled,
    int ConnectionRateLimitPerMinute,
    bool Online,
    long? ConnectedSinceMs,
    long UploadBytes,
    long DownloadBytes,
    string CreatedAt,
    string UpdatedAt);

public sealed record OverviewResponse(
    int Clients,
    int OnlineClients,
    long SuccessfulConnections,
    long FailedConnections,
    long UploadBytes,
    long DownloadBytes,
    int ExternalConnections,
    long RejectedExternalConnections);

public sealed record TunnelMappingView(
    long Id,
    long ClientId,
    string ClientName,
    int ListenPort,
    string TargetAddress,
    int TargetPort,
    bool Enabled,
    bool DetailCaptureEnabled,
    string CreatedAt,
    string UpdatedAt);

public sealed record TunnelMappingMutation(
    int? ListenPort,
    string? TargetAddress,
    int? TargetPort,
    bool? Enabled,
    bool? DetailCaptureEnabled);

public sealed record HttpRouteView(
    long Id,
    long ClientId,
    string ClientName,
    string Route,
    string TargetBaseUrl,
    bool Enabled,
    bool DetailCaptureEnabled,
    bool PathRewriteEnabled,
    string CreatedAt,
    string UpdatedAt);

public sealed record HttpRouteMutation(
    string? Route,
    string? TargetBaseUrl,
    bool? Enabled,
    bool? DetailCaptureEnabled,
    bool? PathRewriteEnabled);

public sealed record NatControlPushResponse(int Pushed, int Tunnels, int HttpRoutes);

public sealed record ConnectionRecordView(
    long Id,
    long? ClientId,
    string ClientName,
    string? ChannelId,
    string? RemoteAddress,
    string ConnectedAt,
    string? DisconnectedAt,
    bool Success,
    string? FailureReason,
    string? DisconnectReason,
    string? DisconnectReasonText);

public sealed record ConnectionEvent(string? TenantId, string Type, ConnectionRecordView Connection);

public sealed record ConnectionPageResponse(
    IReadOnlyList<ConnectionRecordView> Items,
    long Total,
    int Page,
    int Size,
    int TotalPages);

public sealed record TrafficUsageView(
    long Id,
    long ClientId,
    string ClientName,
    string UsageDate,
    long UploadBytes,
    long DownloadBytes,
    string UpdatedAt);

public sealed record ResourceTrafficUsageView(
    long Id,
    long ClientId,
    string ClientName,
    string ResourceType,
    string ResourceKey,
    long? ResourceId,
    string ResourceName,
    string UsageDate,
    long UploadBytes,
    long DownloadBytes,
    string UpdatedAt);

public sealed record HttpTrafficExchangeView(
    string Id,
    long ClientId,
    string ClientName,
    string Route,
    long? ResourceId,
    string? ResourceName,
    string Method,
    string RelativePath,
    string? RawQuery,
    int StatusCode,
    bool Success,
    string? Error,
    string? RemoteAddress,
    long RequestBytes,
    long ResponseBytes,
    long ElapsedMs,
    string? RequestContentType,
    string? ResponseContentType,
    string ResponseBodyType,
    string? RequestHeaders,
    string? ResponseHeaders,
    string? RequestPreviewHex,
    string? RequestPreviewText,
    string? ResponsePreviewHex,
    string? ResponsePreviewText,
    bool RequestTruncated,
    bool ResponseTruncated,
    string CapturedAt);

public sealed record TcpTrafficFrameView(
    string Id,
    long ClientId,
    string ClientName,
    int ListenPort,
    long? ResourceId,
    string? ResourceName,
    string ChannelId,
    string Direction,
    string? RemoteAddress,
    string? SourceAddress,
    int? SourcePort,
    string? DestinationAddress,
    int? DestinationPort,
    long StreamOffset,
    long StreamEndOffset,
    long FrameIndex,
    long PayloadBytes,
    string? PayloadBase64,
    string? PayloadPreviewHex,
    string? PayloadPreviewText,
    bool Truncated,
    string FrameTime);

public sealed record TrafficDetailPage<T>(
    IReadOnlyList<T> Items,
    long Total,
    int Page,
    int Size,
    int TotalPages);

public sealed record ConnectionStatView(
    long Id,
    long? ClientId,
    string ClientName,
    string Month,
    long Total,
    long Success,
    long Failure,
    string UpdatedAt);
