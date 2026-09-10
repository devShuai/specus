using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// The consumer data plane, tested from the leak side.
/// </summary>
/// <remarks>
/// Almost every case here asks the same question in a different way: can a destination the user
/// routed through an egress end up going out locally instead? A connection that fails is a bad
/// afternoon; a connection that silently uses the wrong source address is the thing the user
/// installed this to prevent.
/// </remarks>
public class PeerEgressConsumerTests
{
    private const long Epoch = 1_800_000_000_000L;
    private const string VirtualIp = "100.96.0.1";

    private readonly List<long> _sentTo = [];
    private readonly List<byte[]> _sentFrames = [];
    private readonly List<byte[]> _toTun = [];
    private bool _sendFails;

    private PeerEgressConsumer NewConsumer(
        IReadOnlyList<PeerEgressRule> rules, IReadOnlyDictionary<long, bool> online)
    {
        var consumer = new PeerEgressConsumer(
            (egress, frame) =>
            {
                if (_sendFails)
                {
                    return false;
                }
                _sentTo.Add(egress);
                _sentFrames.Add((byte[])frame.Clone());
                return true;
            },
            packet => _toTun.Add((byte[])packet.Clone()));
        consumer.Configure(rules, PeerEgressRules.DefaultMeshCidr, VirtualIp, Epoch);
        foreach (var (egress, up) in online)
        {
            consumer.SetEgressOnline(egress, up, Epoch);
        }
        return consumer;
    }

    private static PeerEgressRule Rule(string match, string action, long? target = null) => new()
    {
        Match = match,
        Action = action,
        EgressClientId = target,
    };

    private static List<PeerEgressRule> ConsumerRules() =>
    [
        Rule("203.0.113.0/24", PeerEgressRules.ActionEgress, 2),
        Rule("192.0.2.0/24", PeerEgressRules.ActionBlock),
        Rule("198.51.100.0/24", PeerEgressRules.ActionDirect),
    ];

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }

    private static byte[] PacketTo(string destination, ushort port) =>
        PeerEgressSegment.Build(new Segment(
            Address(VirtualIp), Address(destination), 40000, port,
            1000, 0, PeerEgressSegment.FlagSyn, 65535, 0, []));

    private static byte[] ReplyFrame(string source, string destination, ushort sourcePort, ushort destinationPort)
    {
        var packet = PeerEgressSegment.Build(new Segment(
            Address(source), Address(destination), sourcePort, destinationPort,
            1, 1001, PeerEgressSegment.FlagSyn | PeerEgressSegment.FlagAck, 65535, 0, []));
        return PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, packet);
    }

    [Fact]
    public void ForwardsAMatchedDestination()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });

        Assert.Equal(PeerEgressConsumerOutcome.Forwarded,
            consumer.HandleOutbound(PacketTo("203.0.113.10", 443), Epoch));
        Assert.Single(_sentFrames);
        Assert.Equal(2, _sentTo[0]);

        var decoded = PeerEgressFrame.Parse(_sentFrames[0]);
        Assert.True(decoded.Accepted, $"the frame we built does not parse: {decoded.Code}");
        // hop stays clear: this node is a consumer, not an egress forwarding for another one.
        Assert.False(decoded.Hop, "the hop flag was set, which an egress refuses");
        Assert.Equal("203.0.113.10", decoded.Inner.DestinationIp);
    }

    /// <summary>
    /// Traffic no rule claims is not this layer's business. Claiming it would swallow the mesh's
    /// own packets, which share the device.
    /// </summary>
    [Fact]
    public void LeavesUnclaimedTrafficAlone()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });

        foreach (var destination in new[] { "8.8.8.8", "198.51.100.10", "100.96.0.5" })
        {
            Assert.True(
                consumer.HandleOutbound(PacketTo(destination, 443), Epoch) == PeerEgressConsumerOutcome.NotMine,
                destination);
        }
        Assert.Empty(_sentFrames);
    }

    /// <summary>
    /// The whole point. An egress that cannot take the flow means the packet is dropped, never
    /// handed back to the local stack.
    /// </summary>
    [Fact]
    public void BlocksWhenTheEgressIsUnavailable()
    {
        var neverOnline = NewConsumer(ConsumerRules(), new Dictionary<long, bool>());
        Assert.True(
            neverOnline.HandleOutbound(PacketTo("203.0.113.10", 443), Epoch)
                == PeerEgressConsumerOutcome.BlockedNoEgress,
            "never online");

        var wentOffline = NewConsumer(ConsumerRules(), new Dictionary<long, bool>());
        wentOffline.SetEgressOnline(2, true, Epoch);
        wentOffline.SetEgressOnline(2, false, Epoch);
        Assert.True(
            wentOffline.HandleOutbound(PacketTo("203.0.113.10", 443), Epoch)
                == PeerEgressConsumerOutcome.BlockedNoEgress,
            "went offline");

        var sendBroken = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });
        _sendFails = true;
        Assert.True(
            sendBroken.HandleOutbound(PacketTo("203.0.113.10", 443), Epoch)
                == PeerEgressConsumerOutcome.BlockedNoEgress,
            "the send fails");
        _sendFails = false;
    }

    [Fact]
    public void BlocksWhatABlockRuleClaims()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });

        Assert.Equal(PeerEgressConsumerOutcome.BlockedByRule,
            consumer.HandleOutbound(PacketTo("192.0.2.10", 443), Epoch));
        Assert.Empty(_sentFrames);
    }

    /// <summary>
    /// ICMP has no egress in this version. The rule still says this destination must not go out
    /// locally, so it is dropped rather than handed back.
    /// </summary>
    [Fact]
    public void DropsProtocolsItCannotCarry()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });

        var packet = new byte[28];
        packet[0] = 0x45;
        packet[3] = 28;
        packet[9] = 1; // ICMP
        new byte[] { 100, 96, 0, 1 }.CopyTo(packet, 12);
        new byte[] { 203, 0, 113, 10 }.CopyTo(packet, 16);

        Assert.Equal(PeerEgressConsumerOutcome.Unsupported, consumer.HandleOutbound(packet, Epoch));
        Assert.Empty(_sentFrames);
    }

    /// <summary>Four ways the return path could be abused, each closed by its own check.</summary>
    [Fact]
    public void RefusesReturnTrafficItDidNotAskFor()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });
        consumer.HandleOutbound(PacketTo("203.0.113.10", 443), Epoch);

        // Addressed to somebody else's virtual IP.
        consumer.HandleInbound(ReplyFrame("203.0.113.10", "100.96.0.9", 443, 40000), 2, Epoch);
        // Claiming a mesh address, which would let an egress speak as another peer.
        consumer.HandleInbound(ReplyFrame("100.96.0.5", VirtualIp, 443, 40000), 2, Epoch);
        // From an address no flow of ours is talking to.
        consumer.HandleInbound(ReplyFrame("198.51.100.10", VirtualIp, 443, 40000), 2, Epoch);
        // From the right address but the wrong egress.
        consumer.HandleInbound(ReplyFrame("203.0.113.10", VirtualIp, 443, 40000), 3, Epoch);

        Assert.True(_toTun.Count == 0, $"{_toTun.Count} forged replies reached the local stack");

        // The genuine reply does get through, so the checks above are not simply refusing everything.
        consumer.HandleInbound(ReplyFrame("203.0.113.10", VirtualIp, 443, 40000), 2, Epoch);
        Assert.True(_toTun.Count == 1, "the genuine reply did not reach the local stack");
    }

    /// <summary>
    /// An established flow survives a rule change that still sends it to the same egress, and does
    /// not survive one that stops.
    /// </summary>
    [Fact]
    public void PurgesFlowsARuleChangeInvalidates()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });
        consumer.HandleOutbound(PacketTo("203.0.113.10", 443), Epoch);
        Assert.Equal(1, consumer.FlowCount);

        var widened = ConsumerRules();
        widened.Add(Rule("10.1.0.0/16", PeerEgressRules.ActionBlock));
        var unchanged = consumer.Configure(widened, PeerEgressRules.DefaultMeshCidr, VirtualIp, Epoch);
        Assert.True(unchanged.Count == 0, "an unrelated rule addition purged something");
        Assert.Equal(1, consumer.FlowCount);

        var purge = consumer.Configure(
            [Rule("203.0.113.0/24", PeerEgressRules.ActionBlock)],
            PeerEgressRules.DefaultMeshCidr, VirtualIp, Epoch);

        Assert.True(consumer.FlowCount == 0, "a flow survived the rule change");
        Assert.Equal(["203.0.113.10/32"], purge[2]);
    }

    /// <summary>
    /// Without the purge the egress holds the socket until its own idle timer, and the user sees a
    /// connection that is dead at one end and open at the other.
    /// </summary>
    [Fact]
    public void PurgesFlowsWhenTheEgressGoesOffline()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });
        consumer.HandleOutbound(PacketTo("203.0.113.10", 443), Epoch);
        consumer.HandleOutbound(PacketTo("203.0.113.11", 443), Epoch);

        var purge = consumer.SetEgressOnline(2, false, Epoch);
        Assert.True(consumer.FlowCount == 0, "flows survived the egress going offline");
        // Sorted, so two runs of the same change produce the same message.
        Assert.Equal(["203.0.113.10/32", "203.0.113.11/32"], purge[2]);
    }

    /// <summary>
    /// A flow-reject is diagnostic, but it does tell the consumer this flow is over, so the entry
    /// goes rather than lingering until something else clears it.
    /// </summary>
    [Fact]
    public void DropsAFlowTheEgressRejected()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });
        consumer.HandleOutbound(PacketTo("203.0.113.10", 443), Epoch);

        var body = PeerEgressFrame.EncodeControl(PeerEgressFrame.Control.FlowReject(
            "tcp", VirtualIp, 40000, "203.0.113.10", 443, PeerEgressCodes.PortDenied));
        consumer.HandleInbound(PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, body), 2, Epoch);

        Assert.True(consumer.FlowCount == 0, "a flow survived a flow-reject");
        Assert.Equal(1, consumer.BlockedCounts()["rejected-egress_port_denied"]);
    }

    /// <summary>
    /// Counted by reason and never by destination. A per-destination record would be the user's own
    /// browsing history, which is the same reason the egress report aggregates by code.
    /// </summary>
    [Fact]
    public void CountsBlocksByReasonOnly()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool>());
        consumer.HandleOutbound(PacketTo("192.0.2.10", 443), Epoch);
        consumer.HandleOutbound(PacketTo("192.0.2.11", 443), Epoch);
        consumer.HandleOutbound(PacketTo("203.0.113.10", 443), Epoch);

        var counts = consumer.BlockedCounts();
        Assert.Equal(2, counts["rule"]);
        Assert.Equal(1, counts["egress-unavailable"]);
        foreach (var reason in counts.Keys)
        {
            foreach (var destination in new[] { "192.0.2", "203.0.113" })
            {
                Assert.False(reason.StartsWith(destination, StringComparison.Ordinal),
                    $"a destination leaked into the counters as {reason}");
            }
        }
    }

    [Fact]
    public void IgnoresNonEgressFrames()
    {
        var consumer = NewConsumer(ConsumerRules(), new Dictionary<long, bool> { [2] = true });
        var bare = PeerEgressSegment.Build(new Segment(
            Address("203.0.113.10"), Address(VirtualIp), 443, 40000,
            0, 0, PeerEgressSegment.FlagAck, 65535, 0, []));
        Assert.False(consumer.HandleInbound(bare, 2, Epoch),
            "a bare IPv4 packet was claimed by the egress return path");
    }
}
