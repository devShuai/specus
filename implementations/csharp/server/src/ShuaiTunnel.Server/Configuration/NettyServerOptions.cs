using System.Globalization;

namespace ShuaiTunnel.Server.Configuration;

/// <summary>
/// Control-channel and NAT listener limits. The names mirror Java's <c>tunnel.netty.*</c>
/// properties so existing deployment variables keep working, while the values drive .NET socket
/// binding, frame-size protection, and backpressure thresholds.
/// </summary>
public sealed class NettyServerOptions
{
    public const string SectionName = "Tunnel:Netty";

    public int Port { get; set; } = 7010;

    /// <summary>
    /// Hard cap on a single decoded frame (bytes). The reader closes the connection if it sees
    /// a header advertising a length above this — protects against runaway memory on a malformed
    /// peer.
    /// </summary>
    public int MaxFrameSize { get; set; } = 32 * 1024 * 1024;

    public int WriteBufferLowWaterMark { get; set; } = 32 * 1024;

    public int WriteBufferHighWaterMark { get; set; } = 64 * 1024;

    public int MaxExternalConnections { get; set; } = 10_000;

    public int MaxExternalConnectionsPerClient { get; set; } = 10_000;

    public int MaxExternalConnectionsPerPort { get; set; } = 10_000;
}

/// <summary>
/// Login worker-pool thresholds. The defaults mirror Java's bounded executor and keep HMAC/DB
/// login work off the control-channel read loops.
/// </summary>
public sealed class LoginExecutorOptions
{
    public const string SectionName = "Tunnel:Login";

    public int ExecutorCoreSize { get; set; } = 8;
    public int ExecutorMaxSize { get; set; } = 32;
    public int ExecutorQueueCapacity { get; set; } = 20_000;
}

public sealed class DatabaseOptions
{
    public const string SectionName = "Tunnel:Database";

    /// <summary>
    /// Selects the EF Core provider: <c>sqlite</c> (default), <c>postgres</c>/<c>postgresql</c>/<c>npgsql</c>,
    /// or <c>mysql</c>/<c>mariadb</c>. Override via <c>Tunnel:Database:Provider</c> or the Java-style
    /// <c>TUNNEL_DB_PROVIDER</c> env var; pair it with <c>ConnectionStrings:Tunnel</c>
    /// (<c>TUNNEL_CONNECTIONSTRINGS_TUNNEL</c>).
    /// </summary>
    public string Provider { get; set; } = "sqlite";

    public bool SeedDemoClient { get; set; } = true;
}

public sealed class TunnelOptions
{
    public const string SectionName = "Tunnel";

    public string? PublicAddress { get; set; }
}

public sealed class AuthOptions
{
    public const string SectionName = "Tunnel:Auth";

    public bool PasswordLoginEnabled { get; set; } = true;
    public string Username { get; set; } = "admin";
    public string Password { get; set; } = "admin";
    public string TenantId { get; set; } = "default";
    public string? JwtSecret { get; set; }
    public int TokenTtlSeconds { get; set; } = 8 * 60 * 60;
}

public sealed class ClientAuthOptions
{
    public const string SectionName = "Tunnel:ClientAuth";

    public int DefaultMaxOnlineInstances { get; set; } = 2;
    public int PerMachineUserMaxInstances { get; set; } = 1;
    public int TokenTtlSeconds { get; set; } = 8 * 60 * 60;
}

public sealed class ConnectionRecordOptions
{
    public const string SectionName = "Tunnel:ConnectionRecord";

    public int DetailRetentionDays { get; set; } = 60;
    public int ArchiveIntervalMs { get; set; } = 3_600_000;
}

public sealed class TrafficOptions
{
    public const string SectionName = "Tunnel:Traffic";

    public int FlushIntervalMs { get; set; } = 5_000;
    public bool CaptureDetailEnabled { get; set; } = true;
    public int CapturePreviewBytes { get; set; } = 256;
    public int CaptureHeaderChars { get; set; } = 8192;
    public int CaptureMaxPending { get; set; } = 20_000;
    public int CaptureFlushBatchSize { get; set; } = 1_000;
    public int CaptureFlushIntervalMs { get; set; } = 2_000;
}

public sealed class ElasticsearchOptions
{
    public const string SectionName = "Tunnel:Elasticsearch";

    public string Uris { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string ApiKey { get; set; } = string.Empty;
    public string HttpIndex { get; set; } = "shuai-tunnel-http-traffic";
    public string TcpIndex { get; set; } = "shuai-tunnel-tcp-traffic";
    public string HttpMaxStoreSize { get; set; } = "100GB";
    public string TcpMaxStoreSize { get; set; } = "10GB";

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Uris);

    public IReadOnlyList<Uri> EndpointUris() => Uris
        .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
        .Select(value => new Uri(value.TrimEnd('/')))
        .ToList();

    public long HttpMaxStoreBytes => ParseDataSizeBytes(HttpMaxStoreSize, 100L * 1024 * 1024 * 1024);
    public long TcpMaxStoreBytes => ParseDataSizeBytes(TcpMaxStoreSize, 10L * 1024 * 1024 * 1024);

    private static long ParseDataSizeBytes(string? value, long fallback)
    {
        var normalized = (value ?? string.Empty).Trim().ToUpperInvariant();
        if (normalized.Length == 0)
        {
            return fallback;
        }

        var multiplier = 1L;
        foreach (var (suffix, factor) in new[]
        {
            ("KIB", 1024L),
            ("MIB", 1024L * 1024),
            ("GIB", 1024L * 1024 * 1024),
            ("TIB", 1024L * 1024 * 1024 * 1024),
            ("KB", 1024L),
            ("MB", 1024L * 1024),
            ("GB", 1024L * 1024 * 1024),
            ("TB", 1024L * 1024 * 1024 * 1024),
            ("B", 1L),
        })
        {
            if (!normalized.EndsWith(suffix, StringComparison.Ordinal))
            {
                continue;
            }
            multiplier = factor;
            normalized = normalized[..^suffix.Length].Trim();
            break;
        }

        return long.TryParse(normalized, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) && number >= 0
            ? number * multiplier
            : fallback;
    }
}

public sealed class DirectHttpOptions
{
    public const string SectionName = "Tunnel:Http";

    public int TimeoutMs { get; set; } = 30_000;
    public int MaxRequestBodySize { get; set; } = 16 * 1024 * 1024;
    public int RewriteMaxBodyBytes { get; set; } = 10 * 1024 * 1024;
}

public sealed class PeerMeshOptions
{
    public const string SectionName = "Tunnel:PeerMesh";

    public bool Enabled { get; set; } = false;
    public string Cidr { get; set; } = "100.96.0.0/11";
    public string PublicAddress { get; set; } = string.Empty;
    public int StunTurnPort { get; set; } = 3478;
    public int NatProbeAlternatePort { get; set; } = 0;
    public long SessionTtlSeconds { get; set; } = 3600;
    public long AllocationTtlSeconds { get; set; } = 300;
    public long SessionCleanupIntervalMs { get; set; } = 60000;
}

public sealed class OidcOptions
{
    public const string SectionName = "Tunnel:Oidc";

    public string Issuer { get; set; } = "https://gateway.toys.theshuai.com/auth";
    public string JwkSetUri { get; set; } = "https://gateway.toys.theshuai.com/auth/oauth2/jwks";
    public string AuthorizationEndpoint { get; set; } = "https://gateway.toys.theshuai.com/auth/oauth2/authorize";
    public string TokenEndpoint { get; set; } = "https://gateway.toys.theshuai.com/auth/oauth2/token";
    public string EndSessionEndpoint { get; set; } = "https://gateway.toys.theshuai.com/auth/connect/logout";
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = "http://127.0.0.1:8088/";
    public string Scope { get; set; } = "openid";
    public string Audience { get; set; } = string.Empty;
    public string TenantClaim { get; set; } = "tenant_id";
}

/// <summary>
/// Optional TLS settings shared by Kestrel and the raw TCP control channel. Mode names mirror the
/// Java config, but file mode intentionally supports the C# Phase 5 contract: PKCS12/PFX and PEM.
/// </summary>
public sealed class TlsOptions
{
    public const string SectionName = "Tunnel:Tls";

    public string Mode { get; set; } = "disabled";
    public string? Keystore { get; set; }
    public string? KeystorePassword { get; set; }
    public string? KeyPassword { get; set; }

    public TlsMode ResolveMode() => Mode?.Trim().ToLowerInvariant() switch
    {
        "file" => TlsMode.File,
        "self-signed" or "selfsigned" or "self_signed" => TlsMode.SelfSigned,
        _ => TlsMode.Disabled,
    };
}

public enum TlsMode
{
    Disabled,
    File,
    SelfSigned,
}
