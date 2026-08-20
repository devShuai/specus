using System.Text.Json.Serialization;

namespace Specus.Client.Configuration;

// JSON shape mirrors the Java ClientStartupConfig. Runtime specus mappings are delivered by
// /api/client/auth/login and NAT_CONTROL, not by the local startup file.

/// <summary>
/// Root configuration for the specus client, loaded from <c>client.jsonc</c>.
/// </summary>
public sealed class SpecusClientConfig
{
    public const int DefaultUpdateCheckIntervalHours = 24;
    public const int MinUpdateCheckIntervalHours = 1;
    public const int MaxUpdateCheckIntervalHours = 168;
    public const string DefaultPeerMeshDevice = "noop";
    public const string DefaultPeerMeshTunName = "specus0";
    public const int DefaultPeerMeshMtu = 1280;
    public const int MinPeerMeshMtu = 576;
    public const int MaxPeerMeshMtu = 1280;

    [JsonPropertyName("serverBaseUrl")]
    public string ServerBaseUrl { get; set; } = "";

    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; set; }

    [JsonPropertyName("secret")]
    public string? Secret { get; set; }

    [JsonPropertyName("controlTls")]
    public ControlTlsConfig ControlTls { get; set; } = new();

    [JsonPropertyName("peerMeshDevice")]
    public string PeerMeshDevice { get; set; } = DefaultPeerMeshDevice;

    [JsonPropertyName("peerMeshTunName")]
    public string PeerMeshTunName { get; set; } = DefaultPeerMeshTunName;

    [JsonPropertyName("peerMeshMtu")]
    public int PeerMeshMtu { get; set; } = DefaultPeerMeshMtu;

    [JsonPropertyName("updateCheckEnabled")]
    public bool UpdateEnabled { get; set; } = true;

    [JsonPropertyName("autoUpdate")]
    public bool AutoUpdate { get; set; }

    [JsonPropertyName("updateCheckIntervalHours")]
    public int UpdateCheckIntervalHours { get; set; } = DefaultUpdateCheckIntervalHours;

    public void Normalize()
    {
        ServerBaseUrl = ServerBaseUrl.Trim();
        ApiKey = ApiKey?.Trim();
        Secret = Secret?.Trim();
        ControlTls ??= new ControlTlsConfig();
        ControlTls.Normalize();
        PeerMeshDevice = string.IsNullOrWhiteSpace(PeerMeshDevice)
            ? DefaultPeerMeshDevice
            : PeerMeshDevice.Trim();
        PeerMeshTunName = string.IsNullOrWhiteSpace(PeerMeshTunName)
            ? DefaultPeerMeshTunName
            : PeerMeshTunName.Trim();
        PeerMeshMtu = PeerMeshMtu <= 0
            ? DefaultPeerMeshMtu
            : Math.Clamp(PeerMeshMtu, MinPeerMeshMtu, MaxPeerMeshMtu);
        UpdateCheckIntervalHours = UpdateCheckIntervalHours <= 0
            ? DefaultUpdateCheckIntervalHours
            : Math.Clamp(UpdateCheckIntervalHours, MinUpdateCheckIntervalHours, MaxUpdateCheckIntervalHours);
    }
}

/// <summary>TLS settings shared by the control and data TCP connections.</summary>
public sealed class ControlTlsConfig
{
    /// <summary>
    /// Explicit TLS switch. When omitted, the login response's <c>nettyTls</c> flag is used;
    /// configuring any TLS-specific option also opts the control connections into TLS.
    /// </summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>PEM file containing the explicit trust roots for the control server.</summary>
    [JsonPropertyName("caCertificatePath")]
    public string? CaCertificatePath { get; set; }

    /// <summary>Optional TLS hostname override; defaults to the login response host.</summary>
    [JsonPropertyName("serverName")]
    public string? ServerName { get; set; }

    [JsonPropertyName("insecureSkipVerify")]
    public bool InsecureSkipVerify { get; set; }

    internal void Normalize()
    {
        CaCertificatePath = NullIfEmpty(CaCertificatePath);
        ServerName = NullIfEmpty(ServerName);
    }

    internal bool ResolveEnabled(bool runtimeNettyTls)
    {
        if (Enabled is { } enabled)
        {
            return enabled;
        }
        return runtimeNettyTls || HasTlsOptions;
    }

    internal bool HasTlsOptions
        => CaCertificatePath is not null || ServerName is not null || InsecureSkipVerify;

    private static string? NullIfEmpty(string? value)
    {
        var normalized = value?.Trim();
        return string.IsNullOrEmpty(normalized) ? null : normalized;
    }
}

public sealed class SpecusRuntimeState
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

    [JsonPropertyName("nettyTls")]
    public bool NettyTls { get; set; }

    [JsonPropertyName("maxOnlineInstances")]
    public int MaxOnlineInstances { get; set; } = 2;

    [JsonPropertyName("policy")]
    public ClientPolicy Policy { get; set; } = new();

    [JsonPropertyName("peerMesh")]
    public PeerMeshConfig PeerMesh { get; set; } = new();

    [JsonPropertyName("specusConfigList")]
    public List<SpecusConfigEntry> SpecusConfigList { get; set; } = new();

    [JsonPropertyName("httpSpecusConfigList")]
    public List<HttpSpecusConfigEntry> HttpSpecusConfigList { get; set; } = new();

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

public sealed class ServiceSharingStatus
{
    [JsonPropertyName("deploymentEnabled")]
    public bool DeploymentEnabled { get; set; }

    [JsonPropertyName("configuredEnabled")]
    public bool ConfiguredEnabled { get; set; }

    [JsonPropertyName("effectiveEnabled")]
    public bool EffectiveEnabled { get; set; }

    [JsonPropertyName("mdnsImportEnabled")]
    public bool MdnsImportEnabled { get; set; }

    public static ServiceSharingStatus Of(bool deploymentEnabled, bool configuredEnabled, bool deviceEnabled) => new()
    {
        DeploymentEnabled = deploymentEnabled,
        ConfiguredEnabled = configuredEnabled,
        EffectiveEnabled = deploymentEnabled && configuredEnabled && deviceEnabled,
    };
}

public sealed class LocalPeerService
{
    [JsonPropertyName("serviceId")]
    public string ServiceId { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("transport")]
    public string Transport { get; set; } = "tcp";

    [JsonPropertyName("application")]
    public string Application { get; set; } = "tcp";

    [JsonPropertyName("targetHost")]
    public string TargetHost { get; set; } = "";

    [JsonPropertyName("targetPort")]
    public int TargetPort { get; set; }

    [JsonPropertyName("publishedPort")]
    public int PublishedPort { get; set; }

    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("visibility")]
    public string Visibility { get; set; } = "OWNER";

    [JsonPropertyName("allowedPeerVirtualIps")]
    public List<string> AllowedPeerVirtualIps { get; set; } = [];
}

public sealed class AdvertisedService
{
    [JsonPropertyName("serviceId")]
    public string ServiceId { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("transport")]
    public string Transport { get; set; } = "tcp";

    [JsonPropertyName("application")]
    public string Application { get; set; } = "tcp";

    [JsonPropertyName("publishedPort")]
    public int PublishedPort { get; set; }

    [JsonPropertyName("path")]
    public string? Path { get; set; }
}

public sealed class SpecusConfigSnapshot
{
    [JsonPropertyName("specusConfigList")]
    public List<SpecusConfigEntry> SpecusConfigList { get; set; } = new();

    /// <summary>
    /// Null means the server did not take over HTTP routes. Empty list means clear routes.
    /// </summary>
    [JsonPropertyName("httpSpecusConfigList")]
    public List<HttpSpecusConfigEntry>? HttpSpecusConfigList { get; set; }
}

/// <summary>A single TCP NAT specus registration entry.</summary>
public sealed class SpecusConfigEntry
{
    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("specusAddress")]
    public string SpecusAddress { get; set; } = "";

    [JsonPropertyName("specusPort")]
    public int SpecusPort { get; set; }
}

/// <summary>A single direct-HTTP route mapping (route -&gt; targetBaseUrl).</summary>
public sealed class HttpSpecusConfigEntry
{
    [JsonPropertyName("route")]
    public string Route { get; set; } = "";

    [JsonPropertyName("targetBaseUrl")]
    public string TargetBaseUrl { get; set; } = "";
}
