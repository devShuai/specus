using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.IntegrationTests;

public sealed class TunnelEnvironmentVariablesTests
{
    [Fact]
    public void MapsJavaStyleTunnelVariablesToDotNetConfigurationKeys()
    {
        var variables = new Dictionary<string, string?>
        {
            ["TUNNEL_NETTY_PORT"] = "7011",
            ["TUNNEL_NETTY_MAX_FRAME_SIZE"] = "1024",
            ["TUNNEL_NETTY_WRITE_BUFFER_HIGH_WATER_MARK"] = "2048",
            ["TUNNEL_DB_SEED_DEMO_CLIENT"] = "false",
            ["TUNNEL_LOGIN_EXECUTOR_QUEUE_CAPACITY"] = "7",
            ["TUNNEL_LOGIN_EXECUTOR_CORE"] = "5",
            ["TUNNEL_LOGIN_EXECUTOR_MAX"] = "32",
            ["TUNNEL_LOGIN_EXECUTOR_QUEUE"] = "4096",
            ["TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES"] = "6",
            ["TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES"] = "2",
            ["TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS"] = "1234",
            ["TUNNEL_AUTH_REGISTRATION_ENABLED"] = "true",
            ["TUNNEL_AUTH_TURNSTILE_ALLOWED_HOSTNAMES"] = "tunnel.example.com",
            ["TUNNEL_AUTH_EMAIL_VERIFICATION_ENABLED"] = "true",
            ["TUNNEL_AUTH_SMTP_STARTTLS_REQUIRED"] = "false",
            ["TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS"] = "7",
            ["TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS"] = "15000",
            ["TUNNEL_TRAFFIC_CAPTURE_MAX_PENDING"] = "300",
            ["TUNNEL_TRAFFIC_CAPTURE_DECODE_MAX_BYTES"] = "1048576",
            ["TUNNEL_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE"] = "25",
            ["TUNNEL_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS"] = "500",
            ["TUNNEL_PEER_MESH_ENABLED"] = "true",
            ["TUNNEL_PEER_MESH_CIDR"] = "100.96.0.0/11",
            ["TUNNEL_PEER_MESH_PUBLIC_ADDRESS"] = "turn.example.com",
            ["TUNNEL_PEER_MESH_STUN_TURN_PORT"] = "3478",
            ["TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT"] = "3479",
            ["TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS"] = "stun:stun1.example.com:3478, stun:stun2.example.com:3478",
            ["TUNNEL_PEER_MESH_SESSION_TTL_SECONDS"] = "3600",
            ["TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS"] = "300",
            ["TUNNEL_PEER_MESH_SESSION_CLEANUP_INTERVAL_MS"] = "60000",
            ["TUNNEL_PEER_MESH_RELAY_MIN_PORT"] = "49152",
            ["TUNNEL_PEER_MESH_RELAY_MAX_PORT"] = "49200",
            ["TUNNEL_PEER_MESH_RELAY_WORKER_THREADS"] = "4",
            ["TUNNEL_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY"] = "10000",
            ["TUNNEL_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS"] = "5000",
            ["TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED"] = "true",
            ["TUNNEL_PEER_MESH_TURN_REALM"] = "shuai-tunnel",
            ["TUNNEL_PEER_MESH_TURN_SHARED_SECRET"] = "test-secret",
            ["TUNNEL_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS"] = "3600",
            ["TUNNEL_OBJECT_STORAGE_PROVIDER"] = "aliyun-oss",
            ["TUNNEL_OBJECT_STORAGE_REGION"] = "cn-shanghai",
            ["TUNNEL_OBJECT_STORAGE_UPLOAD_CALLBACK_URL"] = "https://tunnel.example/api/public/transfer/oss-callback",
            ["TUNNEL_OBJECT_STORAGE_DOWNLOAD_OBJECT_URL_TTL_SECONDS"] = "45",
            ["TUNNEL_OBJECT_STORAGE_PREFIX"] = "files",
            ["TUNNEL_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES"] = "1073741824",
            ["TUNNEL_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES"] = "1073741824",
            ["TUNNEL_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM"] = "12",
            ["TUNNEL_OIDC_JWK_SET_URI"] = "https://issuer.example/jwks",
            ["TUNNEL_OIDC_TENANT_CLAIM"] = "org_id",
            ["TUNNEL_TLS_KEYSTORE_PASSWORD"] = "changeit",
        };

        var mapped = TunnelEnvironmentVariables.BuildConfigurationMap(variables);

        Assert.Equal("7011", mapped["Tunnel:Netty:Port"]);
        Assert.Equal("1024", mapped["Tunnel:Netty:MaxFrameSize"]);
        Assert.Equal("2048", mapped["Tunnel:Netty:WriteBufferHighWaterMark"]);
        Assert.Equal("false", mapped["Tunnel:Database:SeedDemoClient"]);
        Assert.Equal("5", mapped["Tunnel:Login:ExecutorCoreSize"]);
        Assert.Equal("32", mapped["Tunnel:Login:ExecutorMaxSize"]);
        Assert.Equal("4096", mapped["Tunnel:Login:ExecutorQueueCapacity"]);
        Assert.Equal("6", mapped["Tunnel:ClientAuth:DefaultMaxOnlineInstances"]);
        Assert.Equal("2", mapped["Tunnel:ClientAuth:PerMachineUserMaxInstances"]);
        Assert.Equal("1234", mapped["Tunnel:ClientAuth:TokenTtlSeconds"]);
        Assert.Equal("true", mapped["Tunnel:Auth:RegistrationEnabled"]);
        Assert.Equal("tunnel.example.com", mapped["Tunnel:Auth:TurnstileAllowedHostnames"]);
        Assert.Equal("true", mapped["Tunnel:Auth:EmailVerificationEnabled"]);
        Assert.Equal("false", mapped["Tunnel:Auth:SmtpStarttlsRequired"]);
        Assert.Equal("7", mapped["Tunnel:ConnectionRecord:DetailRetentionDays"]);
        Assert.Equal("15000", mapped["Tunnel:ConnectionRecord:ArchiveIntervalMs"]);
        Assert.Equal("300", mapped["Tunnel:Traffic:CaptureMaxPending"]);
        Assert.Equal("1048576", mapped["Tunnel:Traffic:CaptureDecodeMaxBytes"]);
        Assert.Equal("25", mapped["Tunnel:Traffic:CaptureFlushBatchSize"]);
        Assert.Equal("500", mapped["Tunnel:Traffic:CaptureFlushIntervalMs"]);
        Assert.Equal("true", mapped["Tunnel:PeerMesh:Enabled"]);
        Assert.Equal("100.96.0.0/11", mapped["Tunnel:PeerMesh:Cidr"]);
        Assert.Equal("turn.example.com", mapped["Tunnel:PeerMesh:PublicAddress"]);
        Assert.Equal("3478", mapped["Tunnel:PeerMesh:StunTurnPort"]);
        Assert.Equal("3479", mapped["Tunnel:PeerMesh:NatProbeAlternatePort"]);
        Assert.Equal("stun:stun1.example.com:3478", mapped["Tunnel:PeerMesh:PublicStunServers:0"]);
        Assert.Equal("stun:stun2.example.com:3478", mapped["Tunnel:PeerMesh:PublicStunServers:1"]);
        Assert.Equal("3600", mapped["Tunnel:PeerMesh:SessionTtlSeconds"]);
        Assert.Equal("300", mapped["Tunnel:PeerMesh:AllocationTtlSeconds"]);
        Assert.Equal("60000", mapped["Tunnel:PeerMesh:SessionCleanupIntervalMs"]);
        Assert.Equal("49152", mapped["Tunnel:PeerMesh:RelayMinPort"]);
        Assert.Equal("49200", mapped["Tunnel:PeerMesh:RelayMaxPort"]);
        Assert.Equal("4", mapped["Tunnel:PeerMesh:RelayWorkerThreads"]);
        Assert.Equal("10000", mapped["Tunnel:PeerMesh:RelayWorkerQueueCapacity"]);
        Assert.Equal("5000", mapped["Tunnel:PeerMesh:RelayTrafficFlushIntervalMs"]);
        Assert.Equal("true", mapped["Tunnel:PeerMesh:TurnAuthRequired"]);
        Assert.Equal("shuai-tunnel", mapped["Tunnel:PeerMesh:TurnRealm"]);
        Assert.Equal("test-secret", mapped["Tunnel:PeerMesh:TurnSharedSecret"]);
        Assert.Equal("3600", mapped["Tunnel:PeerMesh:TurnCredentialTtlSeconds"]);
        Assert.Equal("aliyun-oss", mapped["Tunnel:ObjectStorage:Provider"]);
        Assert.Equal("cn-shanghai", mapped["Tunnel:ObjectStorage:Region"]);
        Assert.Equal("https://tunnel.example/api/public/transfer/oss-callback",
            mapped["Tunnel:ObjectStorage:UploadCallbackUrl"]);
        Assert.Equal("45", mapped["Tunnel:ObjectStorage:DownloadObjectUrlTtlSeconds"]);
        Assert.Equal("files", mapped["Tunnel:ObjectStorage:ObjectPrefix"]);
        Assert.Equal("1073741824", mapped["Tunnel:ObjectStorage:PerUserStorageQuotaBytes"]);
        Assert.Equal("1073741824", mapped["Tunnel:ObjectStorage:PerUserMonthlyDownloadQuotaBytes"]);
        Assert.Equal("12", mapped["Tunnel:PublicTransfer:MaxDiscoveryPeersPerRoom"]);
        Assert.Equal("https://issuer.example/jwks", mapped["Tunnel:Oidc:JwkSetUri"]);
        Assert.Equal("org_id", mapped["Tunnel:Oidc:TenantClaim"]);
        Assert.Equal("changeit", mapped["Tunnel:Tls:KeystorePassword"]);
    }

    [Fact]
    public void PreservesExplicitDoubleUnderscoreConfigurationKeys()
    {
        var variables = new Dictionary<string, string?>
        {
            ["TUNNEL_Tunnel__Netty__Port"] = "7012",
            ["TUNNEL_ConnectionStrings__Tunnel"] = "Data Source=/tmp/tunnel.db",
        };

        var mapped = TunnelEnvironmentVariables.BuildConfigurationMap(variables);

        Assert.Equal("7012", mapped["Tunnel:Netty:Port"]);
        Assert.Equal("Data Source=/tmp/tunnel.db", mapped["ConnectionStrings:Tunnel"]);
    }
}
