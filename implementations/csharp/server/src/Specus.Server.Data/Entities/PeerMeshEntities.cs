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

/// <summary>
/// Stored apart from <see cref="PeerMeshAcl"/> on purpose: mesh ACLs decide whether two devices may
/// reach each other, this decides whether one may be used as a way out to the wider network.
/// Effective permission is the intersection of the two.
/// </summary>
public sealed class PeerMeshEgressPolicy
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public string OwnerUsername { get; set; } = "admin";
    public long EgressClientId { get; set; }
    public string EgressClientName { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public string Scope { get; set; } = "PUBLIC";
    public string AllowedConsumerClientIds { get; set; } = "";

    /// <summary>
    /// A canonical JSON array. Empty denies everything; there is no unconfigured-therefore-open
    /// state.
    /// </summary>
    public string DestinationRules { get; set; } = "[]";
    public int MaxConcurrentFlows { get; set; } = 256;
    public int MaxFlowsPerConsumer { get; set; } = 64;
    public int IdleTimeoutSeconds { get; set; } = 60;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// Latest counters an egress device reported about itself.
/// </summary>
/// <remarks>
/// One row per device rather than an append-only log: the management view needs what the node is
/// doing now, and history from a client-driven message would grow without bound. Counters carry no
/// destination, domain or request content, and refusals arrive aggregated by result code.
/// </remarks>
public sealed class PeerMeshEgressActivity
{
    /// <summary>
    /// Cap on the serialised refusal map. Twenty-six result codes cannot fill it; the cap exists so
    /// a client that invents keys cannot grow the column.
    /// </summary>
    public const int MaxRejectedFlowsBytes = 1024;

    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long EgressClientId { get; set; }
    public string EgressClientName { get; set; } = string.Empty;

    /// <summary>
    /// The control-channel session the report arrived on, bound by the server from the
    /// authenticated connection rather than read out of the message body.
    /// </summary>
    public long SessionId { get; set; }

    /// <summary>Client-supplied snapshot counter; a report older than the stored one is discarded.</summary>
    public long Revision { get; set; }
    public long ActiveFlows { get; set; }
    public long TotalFlows { get; set; }

    /// <summary>Refusals aggregated by result code, as canonical JSON.</summary>
    public string RejectedFlows { get; set; } = "{}";
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public DateTimeOffset ReportedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// Tenant-wide egress switch.
/// </summary>
/// <remarks>
/// Separate from the per-device <c>Enabled</c> on <see cref="PeerMeshEgressPolicy"/>, and both must
/// be on for a device to act as an egress. The per-device flag says whether that device was chosen;
/// this one lets an operator stop the whole tenant at once without losing which devices were
/// configured.
/// </remarks>
public sealed class PeerMeshEgressSwitch
{
    public string TenantId { get; set; } = "default";

    /// <summary>Off by default: egress is opt-in for the tenant as well as per device.</summary>
    public bool Enabled { get; set; }
    public string? UpdatedBy { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
