using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// <c>ipv6PacketCapable</c> in <c>egress-catalog</c> (protocol/spec/peer-egress.md, IPv6 数据面, 能力):
/// read like <c>domainTargetCapable</c>, so only a JSON true says an egress takes IPv6 packets.
/// </summary>
public sealed class PeerEgressCatalogIpv6Tests
{
    [Fact]
    public void OnlyAJsonTrueSaysAnEgressTakesIpv6Packets()
    {
        var message = PeerEgressCatalogMessage.Decode("""
            {"type":"egress-catalog","revision":1,"egresses":[
              {"clientId":2,"ipv6PacketCapable":true},{"clientId":3,"ipv6PacketCapable":"true"},
              {"clientId":4,"ipv6PacketCapable":1},{"clientId":5},{"clientId":6,"ipv6TargetCapable":true},
              {"clientId":7,"domainTargetCapable":true,"ipv6PacketCapable":false}]}
            """);
        Assert.NotNull(message);
        var expected = new Dictionary<long, bool> { [2] = true, [3] = false, [4] = false, [5] = false, [6] = false, [7] = false };
        foreach (var (id, capable) in expected)
        {
            Assert.True(capable == message.Egresses[id].Ipv6PacketCapable, $"egress {id}");
        }
        // The two capabilities are independent: neither implies the other.
        Assert.True(message.Egresses[7].DomainTargetCapable);
        Assert.False(message.Egresses[2].DomainTargetCapable);
    }
}
