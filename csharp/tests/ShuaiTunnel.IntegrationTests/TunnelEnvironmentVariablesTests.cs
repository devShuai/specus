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
        };

        var mapped = TunnelEnvironmentVariables.BuildConfigurationMap(variables);

        Assert.Equal("7011", mapped["Tunnel:Netty:Port"]);
        Assert.Equal("1024", mapped["Tunnel:Netty:MaxFrameSize"]);
        Assert.Equal("2048", mapped["Tunnel:Netty:WriteBufferHighWaterMark"]);
        Assert.Equal("false", mapped["Tunnel:Database:SeedDemoClient"]);
        Assert.Equal("7", mapped["Tunnel:Login:ExecutorQueueCapacity"]);
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
