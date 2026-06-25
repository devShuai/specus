using System.Text.Json;
using ShuaiTunnel.Client.Configuration;

namespace ShuaiTunnel.Client.Tests;

public sealed class TunnelClientConfigLoaderTests
{
    [Fact]
    public void LoadNormalizesPeerMeshOptions()
    {
        var path = Path.Combine(Path.GetTempPath(), $"shuai-tunnel-config-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, """
            {
              "serverBaseUrl": " http://127.0.0.1:8088/ ",
              "apiKey": " demo-client ",
              "secret": " test1234 ",
              "peerMeshDevice": " auto ",
              "peerMeshTunName": " mesh0 ",
              "peerMeshMtu": 4096
            }
            """);

            var config = TunnelClientConfigLoader.Load(path);

            Assert.Equal("http://127.0.0.1:8088/", config.ServerBaseUrl);
            Assert.Equal("demo-client", config.ApiKey);
            Assert.Equal("test1234", config.Secret);
            Assert.Equal("auto", config.PeerMeshDevice);
            Assert.Equal("mesh0", config.PeerMeshTunName);
            Assert.Equal(TunnelClientConfig.MaxPeerMeshMtu, config.PeerMeshMtu);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void LoadDefaultsPeerMeshOptions()
    {
        var path = Path.Combine(Path.GetTempPath(), $"shuai-tunnel-config-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, """
            {
              "serverBaseUrl": "http://127.0.0.1:8088",
              "apiKey": "demo-client",
              "secret": "test1234"
            }
            """);

            var config = TunnelClientConfigLoader.Load(path);

            Assert.Equal(TunnelClientConfig.DefaultPeerMeshDevice, config.PeerMeshDevice);
            Assert.Equal(TunnelClientConfig.DefaultPeerMeshTunName, config.PeerMeshTunName);
            Assert.Equal(TunnelClientConfig.DefaultPeerMeshMtu, config.PeerMeshMtu);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(@"DESKTOP\shshi", "shshi")]
    [InlineData(@"DOMAIN\admin", "admin")]
    [InlineData("root", "root")]
    [InlineData("/users/alice", "alice")]
    [InlineData("  bob  ", "bob")]
    [InlineData("", "unknown")]
    public void NormalizeOsUserMatchesJavaStyleUsername(string input, string expected)
    {
        Assert.Equal(expected, ClientEnvironmentInfo.NormalizeOsUser(input));
    }

    [Fact]
    public void NatControlSnapshotDistinguishesMissingAndEmptyHttpRoutesLikeJava()
    {
        var missing = JsonSerializer.Deserialize<TunnelConfigSnapshot>(
            """{"tunnelConfigList":[]}""",
            TunnelClientConfigLoader.JsonOptions);
        var empty = JsonSerializer.Deserialize<TunnelConfigSnapshot>(
            """{"tunnelConfigList":[],"httpTunnelConfigList":[]}""",
            TunnelClientConfigLoader.JsonOptions);

        Assert.NotNull(missing);
        Assert.Null(missing!.HttpTunnelConfigList);
        Assert.NotNull(empty);
        Assert.NotNull(empty!.HttpTunnelConfigList);
        Assert.Empty(empty.HttpTunnelConfigList);
    }
}
