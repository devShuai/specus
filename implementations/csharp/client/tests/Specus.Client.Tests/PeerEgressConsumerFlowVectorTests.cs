using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Binds when the consumer forgets a flow to <c>peer-egress-consumer-flows-v1.json</c>.
/// </summary>
/// <remarks>
/// Every event goes through the real consumer: an <c>out</c> is a packet read from the TUN, an
/// <c>in</c> the reply arriving from the egress as an SPEG1 frame. Three clients that forget flows at
/// different times would refuse replies the others deliver, and one that never forgets holds every
/// flow it ever made.
/// </remarks>
public class PeerEgressConsumerFlowVectorTests
{
    private const long Epoch = 1_800_000_000_000L;
    private const long Egress = 2L;

    private static JsonDocument Vector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-consumer-flows-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-consumer-flows-v1.json");
    }

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }

    private static int Flags(string letters)
    {
        var flags = 0;
        foreach (var letter in letters)
        {
            flags |= letter switch
            {
                'S' => PeerEgressSegment.FlagSyn,
                'A' => PeerEgressSegment.FlagAck,
                'F' => PeerEgressSegment.FlagFin,
                'R' => PeerEgressSegment.FlagRst,
                'P' => PeerEgressSegment.FlagPsh,
                _ => throw new InvalidOperationException($"unknown TCP flag {letter}"),
            };
        }
        return flags;
    }

    /// <summary>
    /// One consumer with a single egress rule for the remote, and packets in both directions on one
    /// four-tuple per consumer port.
    /// </summary>
    private sealed class Harness
    {
        private readonly string _consumer;
        private readonly string _remote;
        private readonly ushort _remotePort;
        private readonly List<byte[]> _toTun = [];

        public Harness(string consumer, string remote, ushort remotePort, int capacity)
        {
            _consumer = consumer;
            _remote = remote;
            _remotePort = remotePort;
            Consumer = new PeerEgressConsumer((_, _) => true, _toTun.Add, flowCapacity: capacity);
            Consumer.Configure(
                [new PeerEgressRule { Match = remote + "/32", Action = PeerEgressRules.ActionEgress, EgressClientId = Egress }],
                PeerEgressRules.DefaultMeshCidr, consumer, Epoch);
            Consumer.SetEgressOnline(Egress, true, Epoch);
        }

        public PeerEgressConsumer Consumer { get; }

        private static byte[] Packet(int protocol, uint source, uint destination,
            ushort sourcePort, ushort destinationPort, string flags) =>
            protocol == PeerEgressSegment.Ipv4ProtocolTcp
                ? PeerEgressSegment.Build(new PeerEgressSegment.Segment(
                    source, destination, sourcePort, destinationPort, 1000, 2000, Flags(flags), 65535, 0, []))
                : PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(
                    source, destination, sourcePort, destinationPort, "datagram"u8.ToArray()));

        public PeerEgressConsumerOutcome Out(int protocol, ushort port, string flags, long nowMs) =>
            Consumer.HandleOutbound(
                Packet(protocol, Address(_consumer), Address(_remote), port, _remotePort, flags), nowMs);

        /// <summary>"delivered", "return-no-flow", or what went wrong instead.</summary>
        public string In(int protocol, ushort port, string flags, long nowMs)
        {
            var written = _toTun.Count;
            var refused = Consumer.BlockedCounts().GetValueOrDefault("return-no-flow");
            var frame = PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false,
                Packet(protocol, Address(_remote), Address(_consumer), _remotePort, port, flags));
            if (!Consumer.HandleInbound(frame, Egress, nowMs))
            {
                return "not claimed";
            }
            var delivered = _toTun.Count - written;
            var noFlow = Consumer.BlockedCounts().GetValueOrDefault("return-no-flow") - refused;
            return (delivered, noFlow) switch
            {
                (1, 0) => "delivered",
                (0, 1) => "return-no-flow",
                _ => $"delivered={delivered} return-no-flow={noFlow}",
            };
        }

        public bool Remembers(int protocol, ushort port, long nowMs) =>
            Consumer.Remembers(new PeerEgressFlowTable.Key(
                protocol, Address(_consumer), port, Address(_remote), _remotePort), nowMs);
    }

    [Fact]
    public void ForgetsFlowsWhenTheSharedVectorSays()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        Assert.Equal(PeerEgressConsumer.UdpIdleMs, root.GetProperty("udpIdleSeconds").GetInt64() * 1000);
        Assert.Equal(PeerEgressConsumer.TcpIdleMs, root.GetProperty("tcpIdleSeconds").GetInt64() * 1000);
        Assert.Equal(PeerEgressConsumer.TcpClosedLingerMs, root.GetProperty("tcpClosedLingerSeconds").GetInt64() * 1000);
        var consumer = root.GetProperty("consumer").GetString()!;
        var remote = root.GetProperty("remote").GetString()!.Split(':');

        var cases = root.GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "no cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var harness = new Harness(consumer, remote[0], ushort.Parse(remote[1]), testCase.GetProperty("capacity").GetInt32());
            var events = testCase.GetProperty("events").EnumerateArray().ToList();
            var results = testCase.GetProperty("results").EnumerateArray().ToList();
            Assert.True(events.Count == results.Count, $"{name}: {events.Count} events, {results.Count} results");
            // A reply names no protocol: it is the one its port went out on, or TCP when it carries
            // flags and nothing went out.
            var protocols = new Dictionary<ushort, int>();

            for (var i = 0; i < events.Count; i++)
            {
                var step = events[i];
                var nowMs = Epoch + step.GetProperty("at").GetInt64() * 1000;
                var flags = step.TryGetProperty("flags", out var given) ? given.GetString()! : "";
                var label = $"{name} event {i} {step.GetRawText()}";
                object actual;
                if (step.TryGetProperty("out", out var outPort))
                {
                    var port = (ushort)outPort.GetInt32();
                    var protocol = step.GetProperty("protocol").GetString() == "tcp"
                        ? PeerEgressSegment.Ipv4ProtocolTcp
                        : PeerEgressDatagram.Ipv4ProtocolUdp;
                    protocols[port] = protocol;
                    var outcome = harness.Out(protocol, port, flags, nowMs);
                    actual = outcome == PeerEgressConsumerOutcome.Forwarded ? "forwarded" : outcome.ToString();
                }
                else if (step.TryGetProperty("in", out var inPort))
                {
                    var port = (ushort)inPort.GetInt32();
                    var protocol = protocols.TryGetValue(port, out var known)
                        ? known
                        : flags.Length > 0 ? PeerEgressSegment.Ipv4ProtocolTcp : PeerEgressDatagram.Ipv4ProtocolUdp;
                    actual = harness.In(protocol, port, flags, nowMs);
                }
                else if (step.TryGetProperty("known", out var knownPort))
                {
                    var port = (ushort)knownPort.GetInt32();
                    actual = harness.Remembers(PeerEgressSegment.Ipv4ProtocolTcp, port, nowMs)
                        || harness.Remembers(PeerEgressDatagram.Ipv4ProtocolUdp, port, nowMs);
                }
                else
                {
                    // The count an operator reads, not the table's own size.
                    actual = harness.Consumer.StatusSnapshot(nowMs).Flows;
                }

                object expected = results[i].ValueKind switch
                {
                    JsonValueKind.String => results[i].GetString()!,
                    JsonValueKind.True or JsonValueKind.False => results[i].GetBoolean(),
                    JsonValueKind.Number => results[i].GetInt32(),
                    _ => throw new InvalidOperationException($"{label}: unexpected result {results[i]}"),
                };
                Assert.True(expected.Equals(actual), $"{label}: expected {expected}, got {actual}");
            }
        }
    }

    /// <summary>
    /// Expired flows leave the table on the packet path, not only when their own four-tuple is
    /// asked about again. Otherwise the memory the bound exists to release would stay held by
    /// flows nobody returns to.
    /// </summary>
    [Fact]
    public void ReleasesExpiredFlowsNobodyAsksAbout()
    {
        var harness = new Harness("100.96.0.2", "203.0.113.10", 443, PeerEgressConsumer.DefaultFlowCapacity);
        for (ushort port = 10000; port < 10100; port++)
        {
            harness.Out(PeerEgressDatagram.Ipv4ProtocolUdp, port, "", Epoch);
        }
        Assert.Equal(100, harness.Consumer.FlowCount);

        harness.Out(PeerEgressDatagram.Ipv4ProtocolUdp, 20000, "", Epoch + PeerEgressConsumer.UdpIdleMs);

        Assert.Equal(1, harness.Consumer.FlowCount);
    }

    /// <summary>
    /// Of flows last seen in the same millisecond, a full table evicts the one registered first,
    /// whatever order their last packets came in.
    /// </summary>
    [Fact]
    public void EvictsTheFirstRegisteredOfFlowsSeenTogether()
    {
        const int udp = PeerEgressDatagram.Ipv4ProtocolUdp;
        var harness = new Harness("100.96.0.2", "203.0.113.10", 443, 2);
        harness.Out(udp, 1, "", Epoch);
        harness.Out(udp, 2, "", Epoch);
        harness.Out(udp, 2, "", Epoch + 1);
        harness.Out(udp, 1, "", Epoch + 1);

        harness.Out(udp, 3, "", Epoch + 2);

        Assert.False(harness.Remembers(udp, 1, Epoch + 2), "the first registered flow survived");
        Assert.True(harness.Remembers(udp, 2, Epoch + 2), "the later registered flow was evicted");
        Assert.True(harness.Remembers(udp, 3, Epoch + 2), "the new flow was not registered");
    }

    /// <summary>
    /// An expired flow does not count towards a full table, even when it was seen more recently than
    /// the live flow at the front: a closed TCP flow expires two minutes after its close, an open
    /// one two hours after its last packet.
    /// </summary>
    [Fact]
    public void AnExpiredFlowMakesRoomBeforeALiveOneIsEvicted()
    {
        const int tcp = PeerEgressSegment.Ipv4ProtocolTcp;
        var harness = new Harness("100.96.0.2", "203.0.113.10", 443, 2);
        harness.Out(tcp, 1, "S", Epoch);
        harness.Out(tcp, 2, "S", Epoch + 10_000);
        Assert.Equal("delivered", harness.In(tcp, 2, "R", Epoch + 11_000));

        var closedExpires = Epoch + 11_000 + PeerEgressConsumer.TcpClosedLingerMs;
        harness.Out(tcp, 3, "S", closedExpires);

        Assert.True(harness.Remembers(tcp, 1, closedExpires), "a live flow was evicted while an expired one held its place");
        Assert.False(harness.Remembers(tcp, 2, closedExpires), "the closed flow outlived its linger");
        Assert.True(harness.Remembers(tcp, 3, closedExpires), "the new flow was not registered");
    }
}
