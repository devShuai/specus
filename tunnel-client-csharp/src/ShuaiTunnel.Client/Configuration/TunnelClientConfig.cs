using System.Text.Json.Serialization;

namespace ShuaiTunnel.Client.Configuration;

// JSON shape mirrors the Java ClientStartupConfig. Runtime tunnel mappings are delivered by
// /api/client/auth/login and NAT_CONTROL, not by the local startup file.

/// <summary>
/// Root configuration for the tunnel client, loaded from <c>tunnelClientConfig.json</c>.
/// </summary>
public sealed class TunnelClientConfig
{
    [JsonPropertyName("serverBaseUrl")]
    public string ServerBaseUrl { get; set; } = "";

    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; set; }

    [JsonPropertyName("secret")]
    public string? Secret { get; set; }
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
