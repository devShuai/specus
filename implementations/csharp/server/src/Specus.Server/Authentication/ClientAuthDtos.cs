using System.Text.Json.Serialization;
using Specus.Server.PeerMesh;

namespace Specus.Server.Authentication;

public sealed class ClientAuthLoginRequest
{
    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; set; }

    [JsonPropertyName("timestamp")]
    public string? Timestamp { get; set; }

    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }

    [JsonPropertyName("signature")]
    public string? Signature { get; set; }

    [JsonPropertyName("environment")]
    public ClientEnvironmentInfo? Environment { get; set; }
}

public sealed class ClientEnvironmentInfo
{
    [JsonPropertyName("machineFingerprint")]
    public string? MachineFingerprint { get; set; }

    [JsonPropertyName("hostname")]
    public string? Hostname { get; set; }

    [JsonPropertyName("osUser")]
    public string? OsUser { get; set; }

    [JsonPropertyName("osName")]
    public string? OsName { get; set; }

    [JsonPropertyName("osVersion")]
    public string? OsVersion { get; set; }

    [JsonPropertyName("osArch")]
    public string? OsArch { get; set; }

    [JsonPropertyName("clientVersion")]
    public string? ClientVersion { get; set; }

    [JsonPropertyName("javaVersion")]
    public string? JavaVersion { get; set; }

    [JsonPropertyName("peerPublicKey")]
    public string? PeerPublicKey { get; set; }

    [JsonPropertyName("clientMessageCapabilities")]
    public ClientMessageCapabilities ClientMessageCapabilities { get; set; } = new();

    [JsonPropertyName("clientPeerServiceCapabilities")]
    public ClientPeerServiceCapabilities ClientPeerServiceCapabilities { get; set; } = new();

    [JsonPropertyName("localAddresses")]
    public List<string> LocalAddresses { get; set; } = new();

    [JsonPropertyName("startedAt")]
    public string? StartedAt { get; set; }
}

public sealed class ClientMessageCapabilities
{
    [JsonPropertyName("sendMessages")]
    public bool SendMessages { get; set; }

    [JsonPropertyName("receiveMessages")]
    public bool ReceiveMessages { get; set; }

    [JsonPropertyName("attachments")]
    public bool Attachments { get; set; }

    [JsonPropertyName("mediaPreview")]
    public bool MediaPreview { get; set; }

    [JsonPropertyName("maxAttachmentBytes")]
    public long MaxAttachmentBytes { get; set; }
}

public sealed class ClientPeerServiceCapabilities
{
    [JsonPropertyName("version")]
    public int Version { get; set; }

    [JsonPropertyName("applications")]
    public List<string> Applications { get; set; } = new();
}

public sealed class ClientAuthLoginResponse
{
    [JsonPropertyName("tenantId")]
    public string TenantId { get; set; } = "default";

    [JsonPropertyName("clientId")]
    public long ClientId { get; set; }

    [JsonPropertyName("clientName")]
    public string ClientName { get; set; } = "";

    [JsonPropertyName("clientSessionId")]
    public long ClientSessionId { get; set; }

    [JsonPropertyName("accessToken")]
    public string AccessToken { get; set; } = "";

    [JsonPropertyName("tokenTtlSeconds")]
    public long TokenTtlSeconds { get; set; }

    [JsonPropertyName("nettyHost")]
    public string NettyHost { get; set; } = "";

    [JsonPropertyName("nettyPort")]
    public int NettyPort { get; set; }

    [JsonPropertyName("nettyTls")]
    public bool NettyTls { get; set; }

    [JsonPropertyName("maxOnlineInstances")]
    public int MaxOnlineInstances { get; set; } = 2;

    [JsonPropertyName("policy")]
    public ClientPolicy Policy { get; set; } = new();

    [JsonPropertyName("peerMesh")]
    public PeerMeshConfig PeerMesh { get; set; } = new();

    [JsonPropertyName("specusConfigList")]
    public List<SpecusEndpoint> SpecusConfigList { get; set; } = new();

    [JsonPropertyName("httpSpecusConfigList")]
    public List<HttpRouteEndpoint> HttpSpecusConfigList { get; set; } = new();
}

public sealed class ClientPolicy
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("billingStatus")]
    public string BillingStatus { get; set; } = "ACTIVE";

    [JsonPropertyName("retryAfterSeconds")]
    public long RetryAfterSeconds { get; set; }
}

public sealed class PeerMeshConfig
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("clientId")]
    public long ClientId { get; set; }

    [JsonPropertyName("clientName")]
    public string? ClientName { get; set; }

    [JsonPropertyName("virtualIp")]
    public string? VirtualIp { get; set; }

    [JsonPropertyName("cidr")]
    public string? Cidr { get; set; }

    [JsonPropertyName("stunHost")]
    public string? StunHost { get; set; }

    [JsonPropertyName("stunPort")]
    public int StunPort { get; set; }

    [JsonPropertyName("turnHost")]
    public string? TurnHost { get; set; }

    [JsonPropertyName("turnPort")]
    public int TurnPort { get; set; }

    [JsonPropertyName("publicStunServers")]
    public List<string> PublicStunServers { get; set; } = new();

    [JsonPropertyName("iceUsername")]
    public string? IceUsername { get; set; }

    [JsonPropertyName("iceCredential")]
    public string? IceCredential { get; set; }

    [JsonPropertyName("iceRealm")]
    public string? IceRealm { get; set; }

    [JsonPropertyName("iceNonce")]
    public string? IceNonce { get; set; }

    [JsonPropertyName("serverPublicKey")]
    public string? ServerPublicKey { get; set; }

    [JsonPropertyName("clientPublicKey")]
    public string? ClientPublicKey { get; set; }

    [JsonPropertyName("sessionTtlSeconds")]
    public long SessionTtlSeconds { get; set; }

    [JsonPropertyName("peerServiceDiscoveryVersion")]
    public int PeerServiceDiscoveryVersion { get; set; }

    [JsonPropertyName("serviceSharing")]
    public ServiceSharingStatus ServiceSharing { get; set; } = new();

    [JsonPropertyName("localServices")]
    public List<LocalPeerService> LocalServices { get; set; } = new();
}

public sealed class SpecusEndpoint
{
    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("specusAddress")]
    public string SpecusAddress { get; set; } = "";

    [JsonPropertyName("specusPort")]
    public int SpecusPort { get; set; }
}

public sealed class HttpRouteEndpoint
{
    [JsonPropertyName("route")]
    public string Route { get; set; } = "";

    [JsonPropertyName("targetBaseUrl")]
    public string TargetBaseUrl { get; set; } = "";
}
