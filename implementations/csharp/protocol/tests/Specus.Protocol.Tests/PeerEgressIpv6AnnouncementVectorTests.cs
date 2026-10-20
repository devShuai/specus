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

    [Fact]
    public void Ipv6PacketAnnouncementsMatchTheSharedContract()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        string? path = null;
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-ipv6-packet-announcement-v1.json");
            if (File.Exists(candidate)) { path = candidate; break; }
            directory = directory.Parent;
        }
        Assert.NotNull(path);
        using var document = JsonDocument.Parse(File.ReadAllText(path!));
        Assert.Equal("client_egress_ipv6_packets", document.RootElement.GetProperty("sessionColumn").GetString());
        Assert.False(document.RootElement.GetProperty("legacyDefault").GetBoolean());
        var examples = document.RootElement.GetProperty("login");
        Assert.Equal(8, examples.GetArrayLength());
        foreach (var example in examples.EnumerateArray())
        {
            var name = example.GetProperty("name").GetString();
            var capabilities = example.GetProperty("capabilities");
            var version = capabilities.ValueKind == JsonValueKind.Object && capabilities.TryGetProperty("version", out var value)
                ? value.GetInt32() : 0;
            // Only a literal true counts; ipv6TargetCapable never stands in for it.
            var declared = capabilities.ValueKind == JsonValueKind.Object
                && capabilities.TryGetProperty("ipv6PacketCapable", out var flag) && flag.ValueKind == JsonValueKind.True;
            Assert.True(example.GetProperty("normalizedVersion").GetInt32() == PeerEgressProtocol.NormalizeVersion(version),
                $"{name}: wrong normalized version");
            Assert.True(example.GetProperty("stored").GetBoolean() == PeerEgressProtocol.DeclaresIpv6Packets(version, declared),
                $"{name}: wrong stored declaration");
        }
    }

    [Fact]
    public void CatalogEntryWritesIpv6PacketCapableRightAfterIpv6TargetCapable()
    {
        var json = JsonSerializer.Serialize(new PeerEgressCatalogEntry
        {
            ClientId = 2, ClientName = "office-gateway", Online = true, Protocols = ["tcp"],
            Ipv6TargetCapable = false, Ipv6PacketCapable = true, EgressVersion = 1,
        });
        using var document = JsonDocument.Parse(json);
        var names = document.RootElement.EnumerateObject().Select(property => property.Name).ToArray();
        Assert.Equal(
            ["clientId", "clientName", "online", "scope", "protocols", "domainTargetCapable",
                "ipv6TargetCapable", "ipv6PacketCapable", "egressVersion"],
            names);
        Assert.False(document.RootElement.GetProperty("ipv6TargetCapable").GetBoolean());
        Assert.True(document.RootElement.GetProperty("ipv6PacketCapable").GetBoolean());
    }
}
