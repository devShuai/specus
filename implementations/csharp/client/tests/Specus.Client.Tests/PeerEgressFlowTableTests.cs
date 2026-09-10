using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;
using Key = Specus.Client.PeerMesh.PeerEgressFlowTable.Key;

namespace Specus.Client.Tests;

/// <summary>
/// The flow table is what makes a socket legitimate: it holds the quota a policy grants and the
/// record that lets a returning packet be matched to a flow this node actually opened.
/// </summary>
/// <remarks>
/// No shared vector here, unlike the segment and frame layers. Most of this is local resource
/// bookkeeping, where two runtimes disagreeing produces no interop failure. The parts that are
/// observable to a peer -- which flows a purge closes, and which reason a revocation carries -- run
/// through the judgment layer, which the authorization vector already drives in all three runtimes.
/// </remarks>
public class PeerEgressFlowTableTests
{
    private const int Tcp = PeerEgressSegment.Ipv4ProtocolTcp;
    private const int Udp = PeerEgressDatagram.Ipv4ProtocolUdp;
    private const long Epoch = 1_800_000_000_000L;

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }

    private static Key MakeKey(int protocol, string consumerIp, int consumerPort, string remoteIp, int remotePort) =>
        new(protocol, Address(consumerIp), (ushort)consumerPort, Address(remoteIp), (ushort)remotePort);

    private static PeerEgressPolicy Policy(params string[] destinations)
    {
        var rules = new List<PeerEgressDestinationRule>();
        foreach (var cidr in destinations)
        {
            rules.Add(new PeerEgressDestinationRule
            {
                Cidr = cidr,
                Protocols = ["tcp", "udp"],
                // An empty portRanges denies every port, so a rule meant to allow traffic says so.
                PortRanges = [[1, 65535]]
            });
        }
        return new PeerEgressPolicy
        {
            Enabled = true,
            Scope = "PUBLIC",
            AllowedConsumerClientIds = [7L, 9L],
            DestinationRules = rules
        };
    }

    /// <summary>A quota that counted TCP and UDP separately would let a consumer double its allowance.</summary>
    [Fact]
    public void CountsFeedTheLimitChecksAcrossBothProtocols()
    {
        var table = new PeerEgressFlowTable(60_000);
        table.Open(MakeKey(Tcp, "100.96.0.1", 40000, "203.0.113.10", 443), 7, Epoch);
        table.Open(MakeKey(Udp, "100.96.0.1", 40000, "203.0.113.10", 443), 7, Epoch);
        table.Open(MakeKey(Udp, "100.96.0.2", 51000, "203.0.113.53", 53), 9, Epoch);

        Assert.Equal(2, table.CountFor(7));
        Assert.Equal(3, table.Count);
        Assert.True(table.CountFor(11) == 0, "an unknown consumer inherited a count");
    }

    /// <summary>
    /// Two datagrams leaving one consumer port for different destinations are separate sessions.
    /// Keying on the source port alone would put the second destination's replies on the first's
    /// socket.
    /// </summary>
    [Fact]
    public void DestinationsSharingASourcePortAreSeparateFlows()
    {
        var table = new PeerEgressFlowTable(60_000);
        Assert.NotNull(table.Open(MakeKey(Udp, "100.96.0.1", 51000, "203.0.113.53", 53), 7, Epoch));
        Assert.NotNull(table.Open(MakeKey(Udp, "100.96.0.1", 51000, "198.51.100.53", 53), 7, Epoch));
        Assert.Equal(2, table.Count);
    }

    /// <summary>A retransmitted SYN is ordinary traffic. Reporting it as new would charge the quota twice.</summary>
    [Fact]
    public void ReopeningReturnsNullAndChargesTheQuotaOnce()
    {
        var table = new PeerEgressFlowTable(60_000);
        var key = MakeKey(Tcp, "100.96.0.1", 40000, "203.0.113.10", 443);
        Assert.NotNull(table.Open(key, 7, Epoch));
        Assert.True(table.Open(key, 7, Epoch + 1000) is null, "a repeated open was reported as new");
        Assert.Equal(1, table.CountFor(7));
        Assert.True(table.Lookup(key)!.LastSeenMs == Epoch + 1000, "activity was not refreshed");
    }

    /// <summary>Nothing in UDP says a session ended, so the idle timer is the only thing that ends one.</summary>
    [Fact]
    public void IdleFlowsExpireAndReleaseTheirQuota()
    {
        var table = new PeerEgressFlowTable(30_000);
        var idle = MakeKey(Udp, "100.96.0.1", 51000, "203.0.113.53", 53);
        var busy = MakeKey(Udp, "100.96.0.1", 51001, "203.0.113.53", 53);
        table.Open(idle, 7, Epoch);
        table.Open(busy, 7, Epoch);

        Assert.Empty(table.Expire(Epoch + 20_000));

        table.Touch(busy, Epoch + 25_000);
        var reaped = table.Expire(Epoch + 40_000);
        Assert.Single(reaped);
        Assert.Equal(idle, reaped[0].Key);
        Assert.True(table.CountFor(7) == 1, "the expired flow did not release its quota slot");
    }

    /// <summary>A revoked consumer must stop being forwarded now, not when it next opens something.</summary>
    [Fact]
    public void RevokingOneConsumerLeavesTheOthersAlone()
    {
        var table = new PeerEgressFlowTable(60_000);
        table.Open(MakeKey(Tcp, "100.96.0.1", 40000, "203.0.113.10", 443), 7, Epoch);
        table.Open(MakeKey(Tcp, "100.96.0.1", 40001, "203.0.113.11", 443), 7, Epoch);
        var survivor = MakeKey(Tcp, "100.96.0.2", 40000, "203.0.113.12", 443);
        table.Open(survivor, 9, Epoch);

        Assert.Equal(2, table.RevokeConsumer(7).Count);
        Assert.Equal(1, table.Count);
        Assert.True(table.Lookup(survivor) is not null, "another consumer's flow was closed");
    }

    /// <summary>
    /// A purge speaks for its sender's flows. Acting on it for everyone would let any consumer tear
    /// down every other consumer's traffic with one message.
    /// </summary>
    [Fact]
    public void PurgeIsScopedToItsSender()
    {
        var table = new PeerEgressFlowTable(60_000);
        table.Open(MakeKey(Tcp, "100.96.0.1", 40000, "203.0.113.10", 443), 7, Epoch);
        var otherConsumer = MakeKey(Tcp, "100.96.0.2", 40000, "203.0.113.10", 443);
        table.Open(otherConsumer, 9, Epoch);

        Assert.Single(table.PurgeDestinations(7, ["203.0.113.0/24"]));
        Assert.True(table.Lookup(otherConsumer) is not null, "one consumer's purge closed another's flow");
    }

    /// <summary>Treating an unreadable prefix as matching everything would turn one bad message into an outage.</summary>
    [Fact]
    public void PurgeIgnoresUnparseablePrefixes()
    {
        var table = new PeerEgressFlowTable(60_000);
        table.Open(MakeKey(Tcp, "100.96.0.1", 40000, "203.0.113.10", 443), 7, Epoch);

        Assert.Empty(table.PurgeDestinations(7, ["not-a-cidr", "203.0.113.1/24"]));
        Assert.True(table.Count == 1, "a malformed purge closed a flow");
    }

    /// <summary>
    /// One policy push can close flows for different reasons at once. A single code for the batch
    /// would tell a consumer its flow died of something that did not happen to it.
    /// </summary>
    [Fact]
    public void ReauthorizeReportsEachFlowsOwnReason()
    {
        var table = new PeerEgressFlowTable(60_000);
        var outsideRule = MakeKey(Tcp, "100.96.0.1", 40000, "198.51.100.10", 443);
        var deniedConsumer = MakeKey(Tcp, "100.96.0.2", 40000, "203.0.113.10", 443);
        var kept = MakeKey(Tcp, "100.96.0.1", 40001, "203.0.113.10", 443);
        table.Open(outsideRule, 7, Epoch);
        table.Open(deniedConsumer, 9, Epoch);
        table.Open(kept, 7, Epoch);

        var narrowed = Policy("203.0.113.0/24") with { AllowedConsumerClientIds = [7L] };
        var revoked = table.Reauthorize(narrowed, _ => true, new PeerEgressContext(), []);

        Assert.Equal(2, revoked.Count);
        foreach (var entry in revoked)
        {
            var expected = entry.Flow.Key.Equals(outsideRule)
                ? PeerEgressCodes.DestinationDenied
                : PeerEgressCodes.ConsumerDenied;
            Assert.Equal(expected, entry.Code);
        }
        Assert.True(table.Lookup(kept) is not null, "a flow the policy still allows was closed");
    }

    /// <summary>
    /// Lowering a quota should stop the next flow, not pick live ones to kill. A limit breach is
    /// not a permission a running flow lost.
    /// </summary>
    [Fact]
    public void ReauthorizeDoesNotEnforceLoweredLimits()
    {
        var table = new PeerEgressFlowTable(60_000);
        table.Open(MakeKey(Tcp, "100.96.0.1", 40000, "203.0.113.10", 443), 7, Epoch);
        table.Open(MakeKey(Tcp, "100.96.0.1", 40001, "203.0.113.10", 443), 7, Epoch);

        var narrowed = Policy("203.0.113.0/24") with
        {
            Limits = new PeerEgressLimits { MaxConcurrentFlows = 1, MaxFlowsPerConsumer = 1 }
        };
        Assert.Empty(table.Reauthorize(narrowed, _ => true, new PeerEgressContext(), []));
    }

    /// <summary>
    /// Without this a peer could hand the egress a packet carrying any source address it liked and
    /// have it relayed into the mesh as though the egress had fetched it.
    /// </summary>
    [Fact]
    public void ReturnPathRequiresAnOpenFlow()
    {
        var table = new PeerEgressFlowTable(60_000);
        var key = MakeKey(Tcp, "100.96.0.1", 40000, "203.0.113.10", 443);
        table.Open(key, 7, Epoch);

        Assert.True(table.HasReturnPath(key));
        Assert.False(
            table.HasReturnPath(MakeKey(Tcp, "100.96.0.1", 40000, "198.51.100.10", 443)),
            "a packet from an address this node never contacted was accepted");
        table.Close(key);
        Assert.False(table.HasReturnPath(key), "a closed flow still admitted return traffic");
    }

    [Fact]
    public void DrainReleasesEverything()
    {
        var table = new PeerEgressFlowTable(60_000);
        table.Open(MakeKey(Tcp, "100.96.0.1", 40000, "203.0.113.10", 443), 7, Epoch);
        table.Open(MakeKey(Udp, "100.96.0.2", 51000, "203.0.113.53", 53), 9, Epoch);

        Assert.Equal(2, table.Drain().Count);
        Assert.Equal(0, table.Count);
        Assert.Equal(0, table.CountFor(7));
        Assert.Equal(0, table.CountFor(9));
    }

    /// <summary>
    /// Every reap emits one record per closed flow. Dictionary order would make those records
    /// differ run to run, and addresses compare unsigned so 10.x does not sort above 200.x.
    /// </summary>
    [Fact]
    public void ReapsInAStableOrder()
    {
        List<Key>? first = null;
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var table = new PeerEgressFlowTable(60_000);
            table.Open(MakeKey(Tcp, "200.0.113.1", 40000, "203.0.113.10", 443), 7, Epoch);
            table.Open(MakeKey(Tcp, "10.0.0.1", 40000, "203.0.113.10", 443), 7, Epoch);
            table.Open(MakeKey(Udp, "10.0.0.1", 40000, "203.0.113.10", 443), 7, Epoch);

            var order = table.Drain().Select(flow => flow.Key).ToList();
            if (first is null)
            {
                first = order;
                continue;
            }
            Assert.True(first.SequenceEqual(order), $"attempt {attempt} produced a different order");
        }

        Assert.NotNull(first);
        Assert.True(first![0].ConsumerIp == Address("10.0.0.1"), "addresses were compared as signed");
        Assert.True(first[2].Protocol == Udp, "TCP did not sort before UDP");
    }
}
