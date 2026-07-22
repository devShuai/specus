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

    public bool PasswordLoginEnabled { get; set; } = false;
    public bool RegistrationEnabled { get; set; } = false;
    public string Username { get; set; } = "admin";
    public string Password { get; set; } = string.Empty;
    public string TenantId { get; set; } = "default";
    public string? JwtSecret { get; set; }
    public int TokenTtlSeconds { get; set; } = 8 * 60 * 60;

    public bool TurnstileEnabled { get; set; } = false;
    public string TurnstileSiteKey { get; set; } = string.Empty;
    public string TurnstileSecretKey { get; set; } = string.Empty;
    public string TurnstileVerifyUrl { get; set; } =
        "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    public string TurnstileAllowedHostnames { get; set; } = string.Empty;

    public bool EmailVerificationEnabled { get; set; } = false;
    public string EmailFromAddress { get; set; } = string.Empty;
    public string EmailFromName { get; set; } = "shuai-tunnel";
    public string EmailSubject { get; set; } = "shuai-tunnel 注册验证码";
    public long EmailCodeTtlSeconds { get; set; } = 600;
    public int EmailMaxAttempts { get; set; } = 5;
    public long EmailResendCooldownSeconds { get; set; } = 60;
    public long EmailCleanupIntervalMs { get; set; } = 3_600_000;

    public string SmtpHost { get; set; } = string.Empty;
    public int SmtpPort { get; set; } = 587;
    public string SmtpUsername { get; set; } = string.Empty;
    public string SmtpPassword { get; set; } = string.Empty;
    public bool SmtpAuth { get; set; } = true;
    public bool SmtpStartTls { get; set; } = true;
    public bool SmtpStartTlsRequired { get; set; } = true;
    public bool SmtpSsl { get; set; } = false;
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
    public bool CaptureDetailEnabled { get; set; } = false;
    public int CapturePreviewBytes { get; set; } = 256;
    public int CaptureHeaderChars { get; set; } = 8192;
    public int CaptureDecodeMaxBytes { get; set; } = 1_048_576;
    public int CaptureMaxPending { get; set; } = 20_000;
    public int CaptureFlushBatchSize { get; set; } = 1_000;
    public int CaptureFlushIntervalMs { get; set; } = 2_000;
    public double CaptureSampleRate { get; set; } = 1.0;
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

public sealed class PublicTransferOptions
{
    public const string SectionName = "Tunnel:PublicTransfer";

    public int PresignRateLimitPerIp { get; set; } = 30;
    public long PresignRateLimitWindowSeconds { get; set; } = 300;
    public int MaxPendingUploadsPerRoom { get; set; } = 50;
    public int MaxDiscoveryPeersPerRoom { get; set; } = 32;
    public int DiscoveryMessageRateLimitPerConnection { get; set; } = 360;
    public long DiscoveryMessageRateLimitWindowSeconds { get; set; } = 60;
    public bool ClusterEnabled { get; set; }
    public string RedisUri { get; set; } = string.Empty;
    public string RedisKeyPrefix { get; set; } = "shuai-tunnel:v2:public-transfer";
    public long PresenceLeaseSeconds { get; set; } = 30;
    public long PresenceRefreshIntervalMs { get; set; } = 10_000;
    public long RedisCommandTimeoutMs { get; set; } = 2_000;
}

public sealed class ObjectStorageOptions
{
    public const string SectionName = "Tunnel:ObjectStorage";

    public string Provider { get; set; } = "disabled";
    public string Endpoint { get; set; } = string.Empty;
    public string Region { get; set; } = string.Empty;
    public string Bucket { get; set; } = string.Empty;
    public string AccessKeyId { get; set; } = string.Empty;
    public string AccessKeySecret { get; set; } = string.Empty;
    public string ObjectPrefix { get; set; } = "shuai-tunnel/attachments";
    public string UploadCallbackUrl { get; set; } = string.Empty;
    public long UploadUrlTtlSeconds { get; set; } = 900;
    public long DownloadUrlTtlSeconds { get; set; } = 600;
    public long DownloadObjectUrlTtlSeconds { get; set; } = 30;
    public long RetentionHours { get; set; } = 72;
    public long MaxAttachmentBytes { get; set; } = 512L * 1024 * 1024;
    public long PerUserStorageQuotaBytes { get; set; } = 1024L * 1024 * 1024;
    public long PerUserMonthlyDownloadQuotaBytes { get; set; } = 1024L * 1024 * 1024;
    public long ExpirationScanIntervalMs { get; set; } = 3_600_000;
}

public sealed class PeerMeshOptions
{
    public const string SectionName = "Tunnel:PeerMesh";

    public bool Enabled { get; set; } = false;
    public string Cidr { get; set; } = "100.96.0.0/11";
    public string PublicAddress { get; set; } = string.Empty;
    public int StunTurnPort { get; set; } = 3478;
    public string StandaloneStunAddress { get; set; } = string.Empty;
    public int StandaloneStunPort { get; set; } = 3478;
    public int NatProbeAlternatePort { get; set; } = 3479;
    public List<string> PublicStunServers { get; set; } = [];
    public long SessionTtlSeconds { get; set; } = 3600;
    public long AllocationTtlSeconds { get; set; } = 300;
    public int RelayMinPort { get; set; } = 49152;
    public int RelayMaxPort { get; set; } = 65535;
    public int RelayWorkerThreads { get; set; }
    public int RelayWorkerQueueCapacity { get; set; } = 10_000;
    public bool TurnAuthRequired { get; set; } = true;
    public string TurnRealm { get; set; } = "shuai-tunnel";
    public string TurnSharedSecret { get; set; } = string.Empty;
    public long TurnCredentialTtlSeconds { get; set; } = 3600;
    public long SessionCleanupIntervalMs { get; set; } = 60000;
    public int RelayTrafficFlushIntervalMs { get; set; } = 5000;
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
