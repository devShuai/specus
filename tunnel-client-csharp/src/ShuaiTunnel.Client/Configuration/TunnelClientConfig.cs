using System.Text.Json.Serialization;

namespace ShuaiTunnel.Client.Configuration;

// JSON shape mirrors tunnelClientConfig.json across the Java/Go clients. Field names follow
// the Java POJO camelCase exactly so the file is interchangeable across implementations.

/// <summary>
/// Root configuration for the tunnel client, loaded from <c>tunnelClientConfig.json</c>.
/// </summary>
public sealed class TunnelClientConfig
{
    [JsonPropertyName("clientName")]
    public string ClientName { get; set; } = "";

    [JsonPropertyName("password")]
    public string Password { get; set; } = "";

    [JsonPropertyName("remoteAddress")]
    public string RemoteAddress { get; set; } = "";

    [JsonPropertyName("remotePort")]
    public int RemotePort { get; set; }

    [JsonPropertyName("tunnelConfigList")]
    public List<TunnelConfigEntry> TunnelConfigList { get; set; } = new();

    /// <summary>
    /// HTTP routes used as a local fallback. A <c>null</c> list (or missing key) means
    /// "server is not managing routes; keep the local fallback"; an empty list clears it.
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
