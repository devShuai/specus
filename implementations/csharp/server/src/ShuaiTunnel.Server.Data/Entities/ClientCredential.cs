namespace ShuaiTunnel.Server.Data.Entities;

/// <summary>
/// Mirrors Java <c>tunnel_client_credential</c>. The stored secret is
/// <c>hex(SHA-256(secret))</c>; login verifies <c>HMAC-SHA256</c> over the canonical startup
/// message with those 32 raw bytes.
/// </summary>
public sealed class ClientCredential
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public string? OwnerUsername { get; set; }
    public string ApiKey { get; set; } = string.Empty;
    public string SecretHash { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public int MaxOnlineInstances { get; set; } = 2;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Mirrors Java <c>tunnel_client_identity</c>, one row per credential + machine + OS user.</summary>
public sealed class ClientIdentity
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long CredentialId { get; set; }
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string MachineFingerprint { get; set; } = string.Empty;
    public string OsUser { get; set; } = string.Empty;
    public string? Hostname { get; set; }
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
}

/// <summary>Mirrors Java <c>tunnel_client_session</c> for HTTP login and control-channel state.</summary>
public sealed class ClientSession
{
    public long Id { get; set; }
    public string TenantId { get; set; } = "default";
    public long CredentialId { get; set; }
    public long IdentityId { get; set; }
    public long ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string TokenHash { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string MachineFingerprint { get; set; } = string.Empty;
    public string OsUser { get; set; } = string.Empty;
    public string? Hostname { get; set; }
    public string? OsName { get; set; }
    public string? OsVersion { get; set; }
    public string? OsArch { get; set; }
    public string? ClientVersion { get; set; }
    public string? JavaVersion { get; set; }
    public string? LocalAddresses { get; set; }
    public bool MessageSendCapable { get; set; }
    public bool MessageReceiveCapable { get; set; }
    public bool MessageAttachmentsCapable { get; set; }
    public bool MessageMediaPreviewCapable { get; set; }
    public long MessageMaxAttachmentBytes { get; set; }
    public DateTimeOffset HttpLoginAt { get; set; }
    public DateTimeOffset? NettyConnectedAt { get; set; }
    public DateTimeOffset? DisconnectedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public string? ChannelId { get; set; }
    public string? RemoteAddress { get; set; }
}
