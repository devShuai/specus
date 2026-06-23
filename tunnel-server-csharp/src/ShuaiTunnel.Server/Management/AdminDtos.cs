namespace ShuaiTunnel.Server.Management;

public sealed record AdminLoginRequest(string? Username, string? Password);

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
    string CreatedAt,
    string UpdatedAt);

public sealed record TunnelMappingMutation(
    int? ListenPort,
    string? TargetAddress,
    int? TargetPort,
    bool? Enabled);

public sealed record HttpRouteView(
    long Id,
    long ClientId,
    string ClientName,
    string Route,
    string TargetBaseUrl,
    bool Enabled,
    string CreatedAt,
    string UpdatedAt);

public sealed record HttpRouteMutation(
    string? Route,
    string? TargetBaseUrl,
    bool? Enabled);

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

public sealed record ConnectionEvent(string Type, ConnectionRecordView Record);

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

public sealed record ConnectionStatView(
    long Id,
    long? ClientId,
    string ClientName,
    string Month,
    long Total,
    long Success,
    long Failure,
    string UpdatedAt);
