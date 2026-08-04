using Specus.Server.Configuration;

namespace Specus.IntegrationTests;

public sealed class SpecusEnvironmentVariablesTests
{
    [Fact]
    public void MapsJavaStyleSpecusVariablesToDotNetConfigurationKeys()
    {
        var variables = new Dictionary<string, string?>
        {
            ["SPECUS_NETTY_PORT"] = "7011",
            ["SPECUS_NETTY_MAX_FRAME_SIZE"] = "1024",
            ["SPECUS_NETTY_WRITE_BUFFER_HIGH_WATER_MARK"] = "2048",
            ["SPECUS_NETTY_BIND_ADDRESS"] = "127.0.0.1",
            ["SPECUS_NETTY_SO_BACKLOG"] = "256",
            ["SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE"] = "8192",
            ["SPECUS_DB_SEED_DEMO_CLIENT"] = "false",
            ["SPECUS_DB_URL"] = "jdbc:postgresql://db.example/specus",
            ["SPECUS_DB_USERNAME"] = "specus_user",
            ["SPECUS_DB_PASSWORD"] = "specus_password",
            ["SPECUS_DB_DRIVER"] = "org.postgresql.Driver",
            ["SPECUS_DB_DIALECT"] = "org.hibernate.dialect.PostgreSQLDialect",
            ["SPECUS_DB_POOL_SIZE"] = "12",
            ["SPECUS_DB_BATCH_SIZE"] = "64",
            ["SPECUS_LOGIN_EXECUTOR_QUEUE_CAPACITY"] = "7",
            ["SPECUS_LOGIN_EXECUTOR_CORE"] = "5",
            ["SPECUS_LOGIN_EXECUTOR_MAX"] = "32",
            ["SPECUS_LOGIN_EXECUTOR_QUEUE"] = "4096",
            ["SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES"] = "6",
            ["SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES"] = "2",
            ["SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS"] = "1234",
            ["SPECUS_AUTH_REGISTRATION_ENABLED"] = "true",
            ["SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES"] = "specus.example.com",
            ["SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED"] = "true",
            ["SPECUS_AUTH_SMTP_STARTTLS_REQUIRED"] = "false",
            ["SPECUS_CONNECTION_DETAIL_RETENTION_DAYS"] = "7",
            ["SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS"] = "15000",
            ["SPECUS_TRAFFIC_CAPTURE_MAX_PENDING"] = "300",
            ["SPECUS_TRAFFIC_CAPTURE_DECODE_MAX_BYTES"] = "1048576",
            ["SPECUS_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE"] = "25",
            ["SPECUS_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS"] = "500",
            ["SPECUS_PEER_MESH_ENABLED"] = "true",
            ["SPECUS_PEER_MESH_CIDR"] = "100.96.0.0/11",
            ["SPECUS_PEER_MESH_PUBLIC_ADDRESS"] = "turn.example.com",
            ["SPECUS_PEER_MESH_STUN_TURN_PORT"] = "3478",
            ["SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS"] = "stun-alt.example.com",
            ["SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT"] = "3480",
            ["SPECUS_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS"] = "stun-public.example.com",
            ["SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT"] = "3479",
            ["SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS"] = "stun:stun1.example.com:3478, stun:stun2.example.com:3478",
            ["SPECUS_PEER_MESH_SESSION_TTL_SECONDS"] = "3600",
            ["SPECUS_PEER_MESH_ALLOCATION_TTL_SECONDS"] = "300",
            ["SPECUS_PEER_MESH_SESSION_CLEANUP_INTERVAL_MS"] = "60000",
            ["SPECUS_PEER_MESH_RELAY_MIN_PORT"] = "49152",
            ["SPECUS_PEER_MESH_RELAY_MAX_PORT"] = "49200",
            ["SPECUS_PEER_MESH_RELAY_WORKER_THREADS"] = "4",
            ["SPECUS_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY"] = "10000",
            ["SPECUS_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS"] = "5000",
            ["SPECUS_PEER_MESH_TURN_AUTH_REQUIRED"] = "true",
            ["SPECUS_PEER_MESH_TURN_REALM"] = "specus",
            ["SPECUS_PEER_MESH_TURN_SHARED_SECRET"] = "test-secret",
            ["SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS"] = "3600",
            ["SPECUS_OBJECT_STORAGE_PROVIDER"] = "aliyun-oss",
            ["SPECUS_OBJECT_STORAGE_REGION"] = "cn-shanghai",
            ["SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL"] = "https://specus.example/api/public/transfer/oss-callback",
            ["SPECUS_OBJECT_STORAGE_DOWNLOAD_OBJECT_URL_TTL_SECONDS"] = "45",
            ["SPECUS_OBJECT_STORAGE_PREFIX"] = "files",
            ["SPECUS_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES"] = "1073741824",
            ["SPECUS_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES"] = "1073741824",
            ["SPECUS_MEDIA_CAPTURE_ENABLED"] = "true",
            ["SPECUS_MEDIA_CAPTURE_ENDPOINT"] = "http://rustfs:9000",
            ["SPECUS_MEDIA_CAPTURE_PREFIX"] = "media-cache",
            ["SPECUS_MEDIA_CAPTURE_MAX_INFLIGHT_PARTS"] = "3",
            ["SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM"] = "12",
            ["SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED"] = "true",
            ["SPECUS_PUBLIC_TRANSFER_REDIS_URI"] = "redis://redis.internal:6379/4",
            ["SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX"] = "test:transfer",
            ["SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS"] = "45",
            ["SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS"] = "12000",
            ["SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS"] = "1500",
            ["SPECUS_OIDC_JWK_SET_URI"] = "https://issuer.example/jwks",
            ["SPECUS_OIDC_TENANT_CLAIM"] = "org_id",
            ["SPECUS_TLS_KEYSTORE_PASSWORD"] = "changeit",
            ["SPECUS_TLS_REQUIRE_ENCRYPTION"] = "true",
            ["SPECUS_TLS_TERMINATED_UPSTREAM"] = "true",
        };

        var mapped = SpecusEnvironmentVariables.BuildConfigurationMap(variables);

        Assert.Equal("7011", mapped["Specus:Netty:Port"]);
        Assert.Equal("1024", mapped["Specus:Netty:MaxFrameSize"]);
        Assert.Equal("2048", mapped["Specus:Netty:WriteBufferHighWaterMark"]);
        Assert.Equal("127.0.0.1", mapped["Specus:Netty:BindAddress"]);
        Assert.Equal("256", mapped["Specus:Netty:SoBacklog"]);
        Assert.Equal("8192", mapped["Specus:Netty:PreAuthMaxFrameSize"]);
        Assert.Equal("false", mapped["Specus:Database:SeedDemoClient"]);
        Assert.Equal("jdbc:postgresql://db.example/specus", mapped["Specus:Database:Url"]);
        Assert.Equal("specus_user", mapped["Specus:Database:Username"]);
        Assert.Equal("specus_password", mapped["Specus:Database:Password"]);
        Assert.Equal("org.postgresql.Driver", mapped["Specus:Database:Driver"]);
        Assert.Equal("org.hibernate.dialect.PostgreSQLDialect", mapped["Specus:Database:Dialect"]);
        Assert.Equal("12", mapped["Specus:Database:PoolSize"]);
        Assert.Equal("64", mapped["Specus:Database:BatchSize"]);
        Assert.Equal("5", mapped["Specus:Login:ExecutorCoreSize"]);
        Assert.Equal("32", mapped["Specus:Login:ExecutorMaxSize"]);
        Assert.Equal("4096", mapped["Specus:Login:ExecutorQueueCapacity"]);
        Assert.Equal("6", mapped["Specus:ClientAuth:DefaultMaxOnlineInstances"]);
        Assert.Equal("2", mapped["Specus:ClientAuth:PerMachineUserMaxInstances"]);
        Assert.Equal("1234", mapped["Specus:ClientAuth:TokenTtlSeconds"]);
        Assert.Equal("true", mapped["Specus:Auth:RegistrationEnabled"]);
        Assert.Equal("specus.example.com", mapped["Specus:Auth:TurnstileAllowedHostnames"]);
        Assert.Equal("true", mapped["Specus:Auth:EmailVerificationEnabled"]);
        Assert.Equal("false", mapped["Specus:Auth:SmtpStarttlsRequired"]);
        Assert.Equal("7", mapped["Specus:ConnectionRecord:DetailRetentionDays"]);
        Assert.Equal("15000", mapped["Specus:ConnectionRecord:ArchiveIntervalMs"]);
        Assert.Equal("300", mapped["Specus:Traffic:CaptureMaxPending"]);
        Assert.Equal("1048576", mapped["Specus:Traffic:CaptureDecodeMaxBytes"]);
        Assert.Equal("25", mapped["Specus:Traffic:CaptureFlushBatchSize"]);
        Assert.Equal("500", mapped["Specus:Traffic:CaptureFlushIntervalMs"]);
        Assert.Equal("true", mapped["Specus:PeerMesh:Enabled"]);
        Assert.Equal("100.96.0.0/11", mapped["Specus:PeerMesh:Cidr"]);
        Assert.Equal("turn.example.com", mapped["Specus:PeerMesh:PublicAddress"]);
        Assert.Equal("3478", mapped["Specus:PeerMesh:StunTurnPort"]);
        Assert.Equal("stun-alt.example.com", mapped["Specus:PeerMesh:StandaloneStunAlternateAddress"]);
        Assert.Equal("3480", mapped["Specus:PeerMesh:StandaloneStunAlternatePort"]);
        Assert.Equal("stun-public.example.com", mapped["Specus:PeerMesh:StunAlternatePublicAddress"]);
        Assert.Equal("3479", mapped["Specus:PeerMesh:NatProbeAlternatePort"]);
        Assert.Equal("stun:stun1.example.com:3478", mapped["Specus:PeerMesh:PublicStunServers:0"]);
        Assert.Equal("stun:stun2.example.com:3478", mapped["Specus:PeerMesh:PublicStunServers:1"]);
        Assert.Equal("3600", mapped["Specus:PeerMesh:SessionTtlSeconds"]);
        Assert.Equal("300", mapped["Specus:PeerMesh:AllocationTtlSeconds"]);
        Assert.Equal("60000", mapped["Specus:PeerMesh:SessionCleanupIntervalMs"]);
        Assert.Equal("49152", mapped["Specus:PeerMesh:RelayMinPort"]);
        Assert.Equal("49200", mapped["Specus:PeerMesh:RelayMaxPort"]);
        Assert.Equal("4", mapped["Specus:PeerMesh:RelayWorkerThreads"]);
        Assert.Equal("10000", mapped["Specus:PeerMesh:RelayWorkerQueueCapacity"]);
        Assert.Equal("5000", mapped["Specus:PeerMesh:RelayTrafficFlushIntervalMs"]);
        Assert.Equal("true", mapped["Specus:PeerMesh:TurnAuthRequired"]);
        Assert.Equal("specus", mapped["Specus:PeerMesh:TurnRealm"]);
        Assert.Equal("test-secret", mapped["Specus:PeerMesh:TurnSharedSecret"]);
        Assert.Equal("3600", mapped["Specus:PeerMesh:TurnCredentialTtlSeconds"]);
        Assert.Equal("aliyun-oss", mapped["Specus:ObjectStorage:Provider"]);
        Assert.Equal("cn-shanghai", mapped["Specus:ObjectStorage:Region"]);
        Assert.Equal("https://specus.example/api/public/transfer/oss-callback",
            mapped["Specus:ObjectStorage:UploadCallbackUrl"]);
        Assert.Equal("45", mapped["Specus:ObjectStorage:DownloadObjectUrlTtlSeconds"]);
        Assert.Equal("files", mapped["Specus:ObjectStorage:ObjectPrefix"]);
        Assert.Equal("1073741824", mapped["Specus:ObjectStorage:PerUserStorageQuotaBytes"]);
        Assert.Equal("1073741824", mapped["Specus:ObjectStorage:PerUserMonthlyDownloadQuotaBytes"]);
        Assert.Equal("true", mapped["Specus:MediaCapture:Enabled"]);
        Assert.Equal("http://rustfs:9000", mapped["Specus:MediaCapture:Endpoint"]);
        Assert.Equal("media-cache", mapped["Specus:MediaCapture:ObjectPrefix"]);
        Assert.Equal("3", mapped["Specus:MediaCapture:MaxInflightParts"]);
        Assert.Equal("12", mapped["Specus:PublicTransfer:MaxDiscoveryPeersPerRoom"]);
        Assert.Equal("true", mapped["Specus:PublicTransfer:ClusterEnabled"]);
        Assert.Equal("redis://redis.internal:6379/4", mapped["Specus:PublicTransfer:RedisUri"]);
        Assert.Equal("test:transfer", mapped["Specus:PublicTransfer:RedisKeyPrefix"]);
        Assert.Equal("45", mapped["Specus:PublicTransfer:PresenceLeaseSeconds"]);
        Assert.Equal("12000", mapped["Specus:PublicTransfer:PresenceRefreshIntervalMs"]);
        Assert.Equal("1500", mapped["Specus:PublicTransfer:RedisCommandTimeoutMs"]);
        Assert.Equal("https://issuer.example/jwks", mapped["Specus:Oidc:JwkSetUri"]);
        Assert.Equal("org_id", mapped["Specus:Oidc:TenantClaim"]);
        Assert.Equal("changeit", mapped["Specus:Tls:KeystorePassword"]);
        Assert.Equal("true", mapped["Specus:Tls:RequireEncryption"]);
        Assert.Equal("true", mapped["Specus:Tls:TerminatedUpstream"]);
    }

    [Fact]
    public void PreservesExplicitDoubleUnderscoreConfigurationKeys()
    {
        var variables = new Dictionary<string, string?>
        {
            ["SPECUS_Specus__Netty__Port"] = "7012",
            ["SPECUS_ConnectionStrings__Specus"] = "Data Source=/tmp/specus.db",
        };

        var mapped = SpecusEnvironmentVariables.BuildConfigurationMap(variables);

        Assert.Equal("7012", mapped["Specus:Netty:Port"]);
        Assert.Equal("Data Source=/tmp/specus.db", mapped["ConnectionStrings:Specus"]);
    }
}
