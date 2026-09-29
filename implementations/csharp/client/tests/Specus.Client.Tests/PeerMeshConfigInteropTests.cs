using System.Text.Json;
using Specus.Client.Configuration;

namespace Specus.Client.Tests;

public class PeerMeshConfigInteropTests
{
    [Theory]
    [InlineData("{}")]
    [InlineData("{\"publicStunServers\":null}")]
    [InlineData("{\"publicStunServers\":[]}")]
    public void MissingOrNullPublicStunIsAnEmptyCollection(string json)
    {
        var config = JsonSerializer.Deserialize<PeerMeshConfig>(json)!;
        Assert.Empty(config.PublicStunServers);
        // The runtime's key and bypass builder enumerate this collection unconditionally.
        Assert.DoesNotContain(config.PublicStunServers, value => !string.IsNullOrWhiteSpace(value));
    }

    [Fact]
    public void PublicStunValuesAndExplicitResetArePreserved()
    {
        var config = JsonSerializer.Deserialize<PeerMeshConfig>(
            """{"publicStunServers":["stun.example.test:3478"]}""")!;
        Assert.Equal("stun.example.test:3478", Assert.Single(config.PublicStunServers));
        config.PublicStunServers = null;
        Assert.Empty(config.PublicStunServers);
    }
}
