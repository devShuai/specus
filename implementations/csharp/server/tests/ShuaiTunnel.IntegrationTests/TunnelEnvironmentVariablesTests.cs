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
            ["TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS"] = "7",
            ["TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS"] = "15000",
            ["TUNNEL_TRAFFIC_CAPTURE_MAX_PENDING"] = "300",
            ["TUNNEL_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE"] = "25",
            ["TUNNEL_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS"] = "500",
            ["TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS"] = "stun:stun1.example.com:3478, stun:stun2.example.com:3478",
            ["TUNNEL_PEER_MESH_RELAY_MIN_PORT"] = "49152",
            ["TUNNEL_PEER_MESH_RELAY_MAX_PORT"] = "49200",
            ["TUNNEL_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY"] = "10000",
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
        Assert.Equal("7", mapped["Tunnel:ConnectionRecord:DetailRetentionDays"]);
        Assert.Equal("15000", mapped["Tunnel:ConnectionRecord:ArchiveIntervalMs"]);
        Assert.Equal("300", mapped["Tunnel:Traffic:CaptureMaxPending"]);
        Assert.Equal("25", mapped["Tunnel:Traffic:CaptureFlushBatchSize"]);
        Assert.Equal("500", mapped["Tunnel:Traffic:CaptureFlushIntervalMs"]);
        Assert.Equal("stun:stun1.example.com:3478", mapped["Tunnel:PeerMesh:PublicStunServers:0"]);
        Assert.Equal("stun:stun2.example.com:3478", mapped["Tunnel:PeerMesh:PublicStunServers:1"]);
        Assert.Equal("49152", mapped["Tunnel:PeerMesh:RelayMinPort"]);
        Assert.Equal("49200", mapped["Tunnel:PeerMesh:RelayMaxPort"]);
        Assert.Equal("10000", mapped["Tunnel:PeerMesh:RelayWorkerQueueCapacity"]);
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
