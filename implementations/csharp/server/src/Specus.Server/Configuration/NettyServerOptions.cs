using System.Globalization;

namespace Specus.Server.Configuration;

/// <summary>
/// Control-channel and NAT listener limits. The names mirror Java's <c>specus.netty.*</c>
/// properties so existing deployment variables keep working, while the values drive .NET socket
/// binding, frame-size protection, and backpressure thresholds.
/// </summary>
public sealed class NettyServerOptions
{
    public const string SectionName = "Specus:Netty";

    public int Port { get; set; } = 7010;

    public string BindAddress { get; set; } = "0.0.0.0";

    public int SoBacklog { get; set; } = 8192;

    public bool ReuseAddress { get; set; } = true;

    public bool KeepAlive { get; set; } = true;

    public bool TcpNoDelay { get; set; } = true;

    /// <summary>
    /// Hard cap on a single decoded frame (bytes). The reader closes the connection if it sees
    /// a header advertising a length above this — protects against runaway memory on a malformed
    /// peer.
    /// </summary>
    public int MaxFrameSize { get; set; } = 32 * 1024 * 1024;

    public int PreAuthMaxFrameSize { get; set; } = 16 * 1024;

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
    public const string SectionName = "Specus:Login";

    public int ExecutorCoreSize { get; set; } = 8;
    public int ExecutorMaxSize { get; set; } = 32;
    public int ExecutorQueueCapacity { get; set; } = 20_000;
}

public sealed class DatabaseOptions
{
    public const string SectionName = "Specus:Database";

    /// <summary>
    /// Selects the EF Core provider: <c>sqlite</c> (default), <c>postgres</c>/<c>postgresql</c>/<c>npgsql</c>,
    /// or <c>mysql</c>/<c>mariadb</c>. Override via <c>Specus:Database:Provider</c> or the Java-style
    /// <c>SPECUS_DB_PROVIDER</c> env var; pair it with <c>ConnectionStrings:Specus</c>
    /// (<c>SPECUS_CONNECTIONSTRINGS_SPECUS</c>).
    /// </summary>
    public string Provider { get; set; } = "sqlite";

    /// <summary>Java-compatible JDBC URL, for example jdbc:sqlite:./specus.db.</summary>
    public string Url { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Driver { get; set; } = string.Empty;
    public string Dialect { get; set; } = string.Empty;
    public int PoolSize { get; set; } = 1;
    public int BatchSize { get; set; } = 50;

    public bool SeedDemoClient { get; set; } = true;
}

public sealed class SpecusOptions
{
    public const string SectionName = "Specus";

    public string? PublicAddress { get; set; }
}

public sealed class AuthOptions
{
    public const string SectionName = "Specus:Auth";

    public bool PasswordLoginEnabled { get; set; } = true;
    public bool RegistrationEnabled { get; set; } = true;
    public string Username { get; set; } = "admin";
    public string Password { get; set; } = "admin";
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
    public string EmailFromName { get; set; } = "specus";
    public string EmailSubject { get; set; } = "specus 注册验证码";
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
    public const string SectionName = "Specus:ClientAuth";

    public int DefaultMaxOnlineInstances { get; set; } = 2;
    public int PerMachineUserMaxInstances { get; set; } = 1;
    public int TokenTtlSeconds { get; set; } = 8 * 60 * 60;
}

public sealed class ConnectionRecordOptions
{
    public const string SectionName = "Specus:ConnectionRecord";

    public int DetailRetentionDays { get; set; } = 60;
    public int ArchiveIntervalMs { get; set; } = 3_600_000;
}

public sealed class TrafficOptions
{
    public const string SectionName = "Specus:Traffic";

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
    public const string SectionName = "Specus:Elasticsearch";

    public string Uris { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string ApiKey { get; set; } = string.Empty;
    public string HttpIndex { get; set; } = "specus-http-traffic";
    public string TcpIndex { get; set; } = "specus-tcp-traffic";
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
    public const string SectionName = "Specus:Http";

    public int TimeoutMs { get; set; } = 30_000;
    public int MaxRequestBodySize { get; set; } = 16 * 1024 * 1024;
    public int RewriteMaxBodyBytes { get; set; } = 10 * 1024 * 1024;
}

public sealed class PublicTransferOptions
{
    public const string SectionName = "Specus:PublicTransfer";

    public int PresignRateLimitPerIp { get; set; } = 30;
    public long PresignRateLimitWindowSeconds { get; set; } = 300;
    public int MaxPendingUploadsPerRoom { get; set; } = 50;
    public int MaxDiscoveryPeersPerRoom { get; set; } = 32;
    public int DiscoveryMessageRateLimitPerConnection { get; set; } = 360;
    public long DiscoveryMessageRateLimitWindowSeconds { get; set; } = 60;
    public bool ClusterEnabled { get; set; }
    public string RedisUri { get; set; } = string.Empty;
    /// <summary>
    /// Redis keyspace prefix. Net-scoped discovery (nets:&lt;netId&gt; index, net-scoped
    /// revisions/routing) changed the keyspace semantics: old and new nodes must never share
    /// one keyspace — upgrade every cluster node together, or bump this prefix for the new fleet.
    /// </summary>
    public string RedisKeyPrefix { get; set; } = "specus:v2:public-transfer";
    public long PresenceLeaseSeconds { get; set; } = 30;
    public long PresenceRefreshIntervalMs { get; set; } = 10_000;
    public long RedisCommandTimeoutMs { get; set; } = 2_000;
    public long PairingCodeTtlSeconds { get; set; } = 300;
    public int PairingCodeRedeemRateLimitPerIp { get; set; } = 10;
    public long PairingCodeRedeemRateLimitWindowSeconds { get; set; } = 300;
}

public sealed class ObjectStorageOptions
{
    public const string SectionName = "Specus:ObjectStorage";

    public string Provider { get; set; } = "disabled";
    public string Endpoint { get; set; } = string.Empty;
    public string Region { get; set; } = string.Empty;
    public string Bucket { get; set; } = string.Empty;
    public string AccessKeyId { get; set; } = string.Empty;
    public string AccessKeySecret { get; set; } = string.Empty;
    public string ObjectPrefix { get; set; } = "specus/attachments";
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
    public const string SectionName = "Specus:PeerMesh";

    public bool Enabled { get; set; } = false;
    public string Cidr { get; set; } = "100.96.0.0/11";
    public string PublicAddress { get; set; } = string.Empty;
    public int StunTurnPort { get; set; } = 3478;
    public string StandaloneStunAddress { get; set; } = string.Empty;
    public int StandaloneStunPort { get; set; } = 3478;
    public string StandaloneStunAlternateAddress { get; set; } = string.Empty;
    public int StandaloneStunAlternatePort { get; set; }
    public string StunAlternatePublicAddress { get; set; } = string.Empty;
    public int NatProbeAlternatePort { get; set; } = 3479;
    public List<string> PublicStunServers { get; set; } = [];
    public long SessionTtlSeconds { get; set; } = 3600;
    public long AllocationTtlSeconds { get; set; } = 300;
    public int RelayMinPort { get; set; } = 49152;
    public int RelayMaxPort { get; set; } = 65535;
    public int RelayWorkerThreads { get; set; }
    public int RelayWorkerQueueCapacity { get; set; } = 10_000;
    public bool TurnAuthRequired { get; set; } = true;
    public string TurnRealm { get; set; } = "specus";
    public string TurnSharedSecret { get; set; } = string.Empty;
    public long TurnCredentialTtlSeconds { get; set; } = 3600;

    // General relay quotas. Browser WebRTC relays DTLS/SRTP, which cannot pass the Peer Mesh
    // specific checks, so those allocations forward with standard TURN semantics and need their
    // own resource limits. Setting GeneralRelayMaxAllocations to 0 disables general relay.
    public int GeneralRelayMaxAllocations { get; set; } = 256;
    public int GeneralRelayMaxAllocationsPerAddress { get; set; } = 4;
    public long GeneralRelayMaxBytes { get; set; } = 512L * 1024 * 1024;
    public long SessionCleanupIntervalMs { get; set; } = 60000;
    public int RelayTrafficFlushIntervalMs { get; set; } = 5000;
}

public sealed class OidcOptions
{
    public const string SectionName = "Specus:Oidc";

    public string Issuer { get; set; } = "https://certus.devshuai.com";
    public string JwkSetUri { get; set; } = "https://certus.devshuai.com/oauth2/jwks";
    public string AuthorizationEndpoint { get; set; } = "https://certus.devshuai.com/oauth2/authorize";
    public string RegistrationEndpoint { get; set; } = "https://certus.devshuai.com/register";
    public string TokenEndpoint { get; set; } = "https://certus.devshuai.com/oauth2/token";
    public string EndSessionEndpoint { get; set; } = "https://certus.devshuai.com/oauth2/logout";
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = "http://127.0.0.1:8088/";
    public string Scope { get; set; } = "openid profile email";
    public string Audience { get; set; } = string.Empty;
    public string TenantClaim { get; set; } = "tenant_id";
}

/// <summary>
/// Optional TLS settings shared by Kestrel and the raw TCP control channel. Mode names mirror the
/// Java config, but file mode intentionally supports the C# Phase 5 contract: PKCS12/PFX and PEM.
/// </summary>
public sealed class TlsOptions
{
    public const string SectionName = "Specus:Tls";

    public string Mode { get; set; } = "disabled";
    public string? Keystore { get; set; }
    public string? KeystorePassword { get; set; }
    public string? KeyPassword { get; set; }
    public bool RequireEncryption { get; set; }
    public bool TerminatedUpstream { get; set; }

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
