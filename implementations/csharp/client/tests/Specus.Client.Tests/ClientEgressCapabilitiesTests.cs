using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// The login environment has to announce egress, or no server will ever make this device an egress.
/// </summary>
/// <remarks>
/// All four servers gate egress-config and egress-catalog on
/// <c>environment.clientEgressCapabilities.version</c> being at least 1. This client did not send
/// the object at all, so in a real deployment no policy ever reached it and its egress data plane
/// was reachable only from tests that handed it a policy directly. Asserted on the serialised JSON,
/// because the wire names are the part the servers read.
/// </remarks>
public class ClientEgressCapabilitiesTests
{
    [Fact]
    public void TheLoginEnvironmentAnnouncesEgressCapabilities()
    {
        var environment = ClientEnvironmentInfo.Collect(NullLogger.Instance);
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(environment));

        Assert.True(document.RootElement.TryGetProperty("clientEgressCapabilities", out var capabilities),
            "the login environment carries no clientEgressCapabilities");
        Assert.True(capabilities.TryGetProperty("version", out var version),
            "clientEgressCapabilities carries no version; every server treats that as 0");
        Assert.True(version.GetInt32() >= 1, "every server skips egress-config below version 1");
        Assert.Equal(PeerEgressProtocol.ProtocolVersion, version.GetInt32());
        Assert.True(capabilities.GetProperty("egressCapable").GetBoolean());
        Assert.Equal(PeerEgressRouteCommanders.TakeoverSupported(),
            capabilities.GetProperty("consumerCapable").GetBoolean());
        // The egress honours name-bind, and dials a name with no A record over IPv6.
        Assert.True(capabilities.GetProperty("domainTargetCapable").GetBoolean());
        Assert.True(capabilities.GetProperty("ipv6TargetCapable").GetBoolean());
        // The packet capability is the egress side of the IPv6 data plane. Whether this device also
        // carries IPv6 as a consumer is a separate answer, which no route takeover means no.
        Assert.True(capabilities.TryGetProperty("ipv6PacketCapable", out var packets),
            "ipv6PacketCapable must be present: the egress accepts IPv6 packets in SPEG1");
        Assert.True(packets.GetBoolean(), "ipv6PacketCapable must be true: the egress accepts IPv6 packets in SPEG1");
        Assert.False(PeerEgressIpv6Plane.PlatformCarriesIpv6 && !PeerEgressRouteCommanders.TakeoverSupported(),
            "the consumer carries IPv6 on a platform with no route takeover");
    }
}
