using System.Net;
using System.Net.Http.Json;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.PeerMesh;
using ShuaiTunnel.Protocol.Security;

namespace ShuaiTunnel.Client.Configuration;

public sealed class ClientAuthService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private readonly TunnelClientConfig _config;
    private readonly HttpClient _http;
    private readonly ILogger<ClientAuthService> _logger;

    public ClientAuthService(TunnelClientConfig config, HttpClient http, ILogger<ClientAuthService> logger)
    {
        _config = config;
        _http = http;
        _logger = logger;
    }

    public async Task<TunnelRuntimeState> LoginAsync(CancellationToken cancellationToken)
    {
        var environment = ClientEnvironmentInfo.Collect(_logger);
        var request = new ClientAuthLoginRequest
        {
            Environment = environment,
            ApiKey = _config.ApiKey?.Trim(),
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(
                System.Globalization.CultureInfo.InvariantCulture),
            Nonce = Guid.NewGuid().ToString("N"),
        };
        request.Signature = SignApiKey(
            request.ApiKey,
            request.Timestamp,
            request.Nonce,
            environment,
            _config.Secret?.Trim());

        var url = $"{TrimTrailingSlash(_config.ServerBaseUrl)}/api/client/auth/login";
        using var response = await _http.PostAsJsonAsync(url, request, JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"客户端 HTTP 登录失败 HTTP {(int)response.StatusCode}: {body}");
        }

        var runtime = JsonSerializer.Deserialize<TunnelRuntimeState>(body, JsonOptions)
            ?? throw new InvalidOperationException("客户端 HTTP 登录返回为空");
        if (string.IsNullOrWhiteSpace(runtime.ClientName)
            || runtime.ClientSessionId <= 0
            || string.IsNullOrWhiteSpace(runtime.AccessToken)
            || string.IsNullOrWhiteSpace(runtime.NettyHost)
            || runtime.NettyPort <= 0)
        {
            throw new InvalidOperationException("客户端 HTTP 登录返回缺少 clientName/session/token/netty endpoint");
        }
        if (runtime.TokenTtlSeconds > 0)
        {
            runtime.TokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(runtime.TokenTtlSeconds);
        }
        runtime.TunnelConfigList ??= new List<TunnelConfigEntry>();
        runtime.HttpTunnelConfigList ??= new List<HttpTunnelConfigEntry>();
        runtime.Policy ??= new ClientPolicy();
        runtime.PeerMesh ??= new PeerMeshConfig();
        _logger.LogInformation(
            "客户端 HTTP 登录成功: clientName={ClientName}, session={Session}, tunnel={Host}:{Port}, tcp={Tcp}, http={Http}, peerMesh={PeerMesh}, maxOnlineInstances={Max}",
            runtime.ClientName,
            runtime.ClientSessionId,
            runtime.NettyHost,
            runtime.NettyPort,
            runtime.TunnelConfigList.Count,
            runtime.HttpTunnelConfigList.Count,
            runtime.PeerMesh.Enabled ? "enabled" : "disabled",
            runtime.MaxOnlineInstances);
        return runtime;
    }

    private static string SignApiKey(
        string? apiKey,
        string? timestamp,
        string? nonce,
        ClientEnvironmentInfo environment,
        string? secret)
    {
        return HmacSigner.SignClientStartup(
            apiKey,
            timestamp,
            nonce,
            environment.MachineFingerprint,
            environment.OsUser,
            HmacSigner.Sha256(secret ?? ""));
    }

    private static string TrimTrailingSlash(string value)
    {
        var normalized = value.Trim();
        while (normalized.EndsWith("/", StringComparison.Ordinal))
        {
            normalized = normalized[..^1];
        }
        return normalized;
    }
}

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

    [JsonPropertyName("localAddresses")]
    public List<string> LocalAddresses { get; set; } = new();

    [JsonPropertyName("startedAt")]
    public string? StartedAt { get; set; }

    public static ClientEnvironmentInfo Collect(ILogger logger)
    {
        var info = new ClientEnvironmentInfo
        {
            MachineFingerprint = BuildMachineFingerprint(),
            Hostname = HostName(),
            OsUser = NormalizeOsUser(Environment.UserName),
            OsName = Environment.OSVersion.Platform.ToString(),
            OsVersion = Environment.OSVersion.VersionString,
            OsArch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
            ClientVersion = typeof(ClientEnvironmentInfo).Assembly.GetName().Version?.ToString(),
            JavaVersion = "",
            PeerPublicKey = PeerKeyStore.PublicKeyBase64(logger),
            StartedAt = DateTimeOffset.UtcNow.ToString("O"),
        };
        try
        {
            info.LocalAddresses = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up
                    && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
                .Select(addr => addr.Address)
                .Where(addr => !IPAddress.IsLoopback(addr)
                    && addr.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .Select(addr => addr.ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "采集本地 IP 失败");
        }
        return info;
    }

    internal static string NormalizeOsUser(string? value)
    {
        var normalized = value?.Trim() ?? "";
        if (normalized.Length == 0)
        {
            return "unknown";
        }
        var slash = Math.Max(normalized.LastIndexOf('\\'), normalized.LastIndexOf('/'));
        if (slash >= 0 && slash + 1 < normalized.Length)
        {
            normalized = normalized[(slash + 1)..];
        }
        return normalized.Length == 0 ? "unknown" : normalized;
    }

    private static string BuildMachineFingerprint()
    {
        try
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var directory = Path.Combine(home, ".shuai-tunnel");
            var file = Path.Combine(directory, "machine-id");
            if (File.Exists(file))
            {
                var existing = File.ReadAllText(file, Encoding.UTF8).Trim();
                if (!string.IsNullOrWhiteSpace(existing))
                {
                    return existing;
                }
            }
            Directory.CreateDirectory(directory);
            var generated = "m_" + Guid.NewGuid();
            File.WriteAllText(file, generated, Encoding.UTF8);
            return generated;
        }
        catch
        {
            var fallback = $"{HostName()}\n{Environment.OSVersion.Platform}\n{System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}";
            return "m_" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fallback)))
                .ToLowerInvariant()[..32];
        }
    }

    private static string HostName()
    {
        try
        {
            return Dns.GetHostName();
        }
        catch
        {
            return "unknown-host";
        }
    }
}
