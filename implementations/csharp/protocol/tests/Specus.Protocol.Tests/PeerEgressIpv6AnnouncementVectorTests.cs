using System.Text.Json;
using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

public sealed class PeerEgressIpv6AnnouncementVectorTests
{
    [Fact]
    public void ExistingIpv6TargetSocketAnnouncementsMatchTheSharedContract()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        string? path = null;
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-ipv6-target-announcement-v1.json");
            if (File.Exists(candidate)) { path = candidate; break; }
            directory = directory.Parent;
        }
        Assert.NotNull(path);
        using var document = JsonDocument.Parse(File.ReadAllText(path!));
        Assert.False(document.RootElement.GetProperty("consumerIpv6DataPlaneEnabled").GetBoolean());
        var examples = document.RootElement.GetProperty("login");
        Assert.Equal(7, examples.GetArrayLength());
        foreach (var example in examples.EnumerateArray())
        {
            var capabilities = example.GetProperty("capabilities");
            var version = capabilities.ValueKind == JsonValueKind.Object && capabilities.TryGetProperty("version", out var value)
                ? value.GetInt32() : 0;
            var declared = capabilities.ValueKind == JsonValueKind.Object
                && capabilities.TryGetProperty("ipv6TargetCapable", out var flag) && flag.GetBoolean();
            Assert.Equal(example.GetProperty("normalizedVersion").GetInt32(), PeerEgressProtocol.NormalizeVersion(version));
            Assert.Equal(example.GetProperty("stored").GetBoolean(), PeerEgressProtocol.DeclaresIpv6Targets(version, declared));
        }
    }
}
