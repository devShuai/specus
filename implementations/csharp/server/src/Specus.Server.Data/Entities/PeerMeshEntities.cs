namespace Specus.Server.Data.Entities;

public sealed class PeerMeshDevice
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public string OwnerUsername { get; set; } = "admin";
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string VirtualIp { get; set; } = string.Empty;
    public string Cidr { get; set; } = string.Empty;
    public string? PublicKey { get; set; }
    public string? NatType { get; set; }
    public string? NatMappingBehavior { get; set; }
    public string? NatFilteringBehavior { get; set; }
    public string? NatBehaviorDiscovery { get; set; }
    public string? LastEndpoint { get; set; }
    public string? VirtualDeviceMode { get; set; }
    public string? VirtualDeviceName { get; set; }
    public string? VirtualDeviceStatus { get; set; }
    public string? VirtualDeviceError { get; set; }
    public DateTimeOffset? VirtualDeviceUpdatedAt { get; set; }
    public bool Enabled { get; set; }
    public DateTimeOffset? LastSeenAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class PeerMeshAcl
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public string OwnerUsername { get; set; } = "admin";
    public long SourceClientId { get; set; }
    public string SourceClientName { get; set; } = string.Empty;
    public long TargetClientId { get; set; }
    public string TargetClientName { get; set; } = string.Empty;
    public bool Allowed { get; set; } = true;
    public string Direction { get; set; } = "OUTBOUND";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class PeerMeshSession
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long SourceClientId { get; set; }
    public string SourceClientName { get; set; } = string.Empty;
    public long TargetClientId { get; set; }
    public string TargetClientName { get; set; } = string.Empty;
    public string PathType { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? TokenHash { get; set; }
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ClosedAt { get; set; }
    public long? RttMillis { get; set; }
    public string? LocalEndpoint { get; set; }
    public string? RemoteEndpoint { get; set; }
    public long DirectBytes { get; set; }
    public long RelayBytes { get; set; }
    public DateTimeOffset? LastTrafficAt { get; set; }
    public DateTimeOffset? LastKeepaliveAt { get; set; }
}

public sealed class PeerMeshServiceSharing
{
    public string TenantId { get; set; } = "default";
    public bool Enabled { get; set; }
    public bool MdnsImportEnabled { get; set; }
    public string? UpdatedBy { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class PeerMeshSharedService
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string ServiceId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Transport { get; set; } = "tcp";
    public string Application { get; set; } = "tcp";
    public string TargetHost { get; set; } = "127.0.0.1";
    public int TargetPort { get; set; }
    public int PublishedPort { get; set; }
    public string Path { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public string Visibility { get; set; } = "OWNER";
    public string AllowedClientIds { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
