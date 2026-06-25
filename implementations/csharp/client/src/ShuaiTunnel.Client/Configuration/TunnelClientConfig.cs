using System.Text.Json.Serialization;

namespace ShuaiTunnel.Client.Configuration;

// JSON shape mirrors the Java ClientStartupConfig. Runtime tunnel mappings are delivered by
// /api/client/auth/login and NAT_CONTROL, not by the local startup file.

/// <summary>
/// Root configuration for the tunnel client, loaded from <c>tunnelClientConfig.json</c>.
/// </summary>
public sealed class TunnelClientConfig
{
    public const string DefaultPeerMeshDevice = "noop";
    public const string DefaultPeerMeshTunName = "shuai0";
    public const int DefaultPeerMeshMtu = 1280;
    public const int MinPeerMeshMtu = 576;
    public const int MaxPeerMeshMtu = 1280;

    [JsonPropertyName("serverBaseUrl")]
    public string ServerBaseUrl { get; set; } = "";

    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; set; }

    [JsonPropertyName("secret")]
    public string? Secret { get; set; }

    [JsonPropertyName("peerMeshDevice")]
    public string PeerMeshDevice { get; set; } = DefaultPeerMeshDevice;

    [JsonPropertyName("peerMeshTunName")]
    public string PeerMeshTunName { get; set; } = DefaultPeerMeshTunName;

    [JsonPropertyName("peerMeshMtu")]
    public int PeerMeshMtu { get; set; } = DefaultPeerMeshMtu;

    public void Normalize()
    {
        ServerBaseUrl = ServerBaseUrl.Trim();
        ApiKey = ApiKey?.Trim();
        Secret = Secret?.Trim();
        PeerMeshDevice = string.IsNullOrWhiteSpace(PeerMeshDevice)
            ? DefaultPeerMeshDevice
            : PeerMeshDevice.Trim();
        PeerMeshTunName = string.IsNullOrWhiteSpace(PeerMeshTunName)
            ? DefaultPeerMeshTunName
            : PeerMeshTunName.Trim();
        PeerMeshMtu = PeerMeshMtu <= 0
            ? DefaultPeerMeshMtu
            : Math.Clamp(PeerMeshMtu, MinPeerMeshMtu, MaxPeerMeshMtu);
    }
}

public sealed class TunnelRuntimeState
{
    [JsonPropertyName("tenantId")]
    public string? TenantId { get; set; }

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

    [JsonPropertyName("maxOnlineInstances")]
    public int MaxOnlineInstances { get; set; } = 2;

    [JsonPropertyName("policy")]
    public ClientPolicy Policy { get; set; } = new();

    [JsonPropertyName("peerMesh")]
    public PeerMeshConfig PeerMesh { get; set; } = new();

    [JsonPropertyName("tunnelConfigList")]
    public List<TunnelConfigEntry> TunnelConfigList { get; set; } = new();

    [JsonPropertyName("httpTunnelConfigList")]
    public List<HttpTunnelConfigEntry> HttpTunnelConfigList { get; set; } = new();

    [JsonIgnore]
    public DateTimeOffset TokenExpiresAt { get; set; }
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

    [JsonPropertyName("iceUsername")]
    public string? IceUsername { get; set; }

    [JsonPropertyName("iceCredential")]
    public string? IceCredential { get; set; }

    [JsonPropertyName("serverPublicKey")]
    public string? ServerPublicKey { get; set; }

    [JsonPropertyName("clientPublicKey")]
    public string? ClientPublicKey { get; set; }

    [JsonPropertyName("sessionTtlSeconds")]
    public long SessionTtlSeconds { get; set; }
}

public sealed class TunnelConfigSnapshot
{
    [JsonPropertyName("tunnelConfigList")]
    public List<TunnelConfigEntry> TunnelConfigList { get; set; } = new();

    /// <summary>
    /// Null means the server did not take over HTTP routes. Empty list means clear routes.
    /// </summary>
    [JsonPropertyName("httpTunnelConfigList")]
    public List<HttpTunnelConfigEntry>? HttpTunnelConfigList { get; set; }
}

/// <summary>A single TCP NAT tunnel registration entry.</summary>
public sealed class TunnelConfigEntry
{
    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("tunnelAddress")]
    public string TunnelAddress { get; set; } = "";

    [JsonPropertyName("tunnelPort")]
    public int TunnelPort { get; set; }
}

/// <summary>A single direct-HTTP route mapping (route -&gt; targetBaseUrl).</summary>
public sealed class HttpTunnelConfigEntry
{
    [JsonPropertyName("route")]
    public string Route { get; set; } = "";

    [JsonPropertyName("targetBaseUrl")]
    public string TargetBaseUrl { get; set; } = "";
}
