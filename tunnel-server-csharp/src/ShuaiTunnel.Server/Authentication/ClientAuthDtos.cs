using System.Text.Json.Serialization;

namespace ShuaiTunnel.Server.Authentication;

public sealed class ClientAuthLoginRequest
{
    [JsonPropertyName("authType")]
    public string? AuthType { get; set; }

    [JsonPropertyName("apiKey")]
    public string? ApiKey { get; set; }

    [JsonPropertyName("secret")]
    public string? Secret { get; set; }

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }

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

    [JsonPropertyName("localAddresses")]
    public List<string> LocalAddresses { get; set; } = new();

    [JsonPropertyName("startedAt")]
    public string? StartedAt { get; set; }
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

    [JsonPropertyName("maxOnlineInstances")]
    public int MaxOnlineInstances { get; set; } = 2;

    [JsonPropertyName("policy")]
    public ClientPolicy Policy { get; set; } = new();

    [JsonPropertyName("tunnelConfigList")]
    public List<TunnelEndpoint> TunnelConfigList { get; set; } = new();

    [JsonPropertyName("httpTunnelConfigList")]
    public List<HttpRouteEndpoint> HttpTunnelConfigList { get; set; } = new();
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

public sealed class TunnelEndpoint
{
    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("tunnelAddress")]
    public string TunnelAddress { get; set; } = "";

    [JsonPropertyName("tunnelPort")]
    public int TunnelPort { get; set; }
}

public sealed class HttpRouteEndpoint
{
    [JsonPropertyName("route")]
    public string Route { get; set; } = "";

    [JsonPropertyName("targetBaseUrl")]
    public string TargetBaseUrl { get; set; } = "";
}
