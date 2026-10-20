using System.Buffers.Binary;
using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// The egress runtime carrying IPv6 (protocol/spec/peer-egress.md, IPv6 数据面, 出口), against
/// protocol/test-vectors/peer-egress-ipv6-v1.json and the refusals that keep a consumer to its own
/// address and out of the mesh. The real-socket half is <see cref="PeerEgressIpv6SocketTests"/>.
/// </summary>
public partial class PeerEgressRuntimeTests
{
    /// <summary>The session peer's mesh IPv4; its derived address is the only source the egress accepts from it.</summary>
    private const string ConsumerMesh = "100.96.0.1";

    private const string ConsumerAddress6 = "fd53:7065:6375:7300::6460:1";

    private static UInt128 Address6(string text)
    {
        Assert.True(Ipv6Cidr.TryParseAddress(text, out var value), $"{text} did not parse");
        return value;
    }

    private static UInt128 Consumer6() => PeerEgressMeshAddress.Derive(Address(ConsumerMesh));

    private static Segment Syn6(ushort sourcePort, string destination, ushort destinationPort) =>
        new(0, 0, sourcePort, destinationPort, 1000, 0, PeerEgressSegment.FlagSyn, 65535, 1360, [],
            Ipv6: true, SourceIp6: Consumer6(), DestinationIp6: Address6(destination));

    private static JsonDocument ReadIpv6Vector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-ipv6-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-ipv6-v1.json");
    }

    private static string HexOf(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    private sealed partial class Harness
    {
        /// <summary>The IPv6 packets the runtime sent back to a consumer, as written.</summary>
        public List<byte[]> Packets6()
        {
            var output = new List<byte[]>();
            foreach (var raw in Snapshot())
            {
                var frame = PeerEgressFrame.Parse(raw, ipv6: true);
                if (frame.Accepted && frame.Type == PeerEgressFrame.TypeIpPacket && frame.Inner.Ipv6)
                {
                    output.Add(frame.Body);
                }
            }
            return output;
        }

        public List<Segment> Segments6() =>
            [.. Packets6().Select(packet => PeerEgressSegment.Parse6(packet)).OfType<Segment>()];

        public List<PeerEgressFrame.Control> Controls()
        {
            var output = new List<PeerEgressFrame.Control>();
            foreach (var raw in Snapshot())
            {
                var frame = PeerEgressFrame.Parse(raw);
                if (frame.Accepted && frame.Type == PeerEgressFrame.TypeControl
                    && PeerEgressFrame.DecodeControl(frame.Body) is { } control)
                {
                    output.Add(control);
                }
            }
            return output;
        }

        public int FrameCount => Snapshot().Count;
    }

    /// <summary>
    /// A returned packet holds to what the spec fixes: version 6, traffic class and flow label zero, hop
    /// limit 64, from the target to the consumer's derived address.
    /// </summary>
    internal static void AssertReturnHeader(byte[] packet, UInt128 source, UInt128 destination)
    {
        Assert.Equal(0x60000000u, BinaryPrimitives.ReadUInt32BigEndian(packet));
        Assert.Equal(PeerEgressIpv6.HopLimit, packet[7]);
        Assert.Equal(Ipv6Cidr.FormatAddress(source), Ipv6Cidr.FormatAddress(PeerEgressIpv6.SourceOf(packet)));
        Assert.Equal(Ipv6Cidr.FormatAddress(destination), Ipv6Cidr.FormatAddress(PeerEgressIpv6.DestinationOf(packet)));
    }

    /// <summary>
    /// An accepted frame the egress refuses by protocol is refused by the runtime with the vector's
    /// code, and nothing is dialled for it.
    /// </summary>
    [Fact]
    public void Ipv6VectorFramesAreRefusedWithTheirEgressCode()
    {
        using var vector = ReadIpv6Vector();
        var refusals = 0;
        foreach (var testCase in vector.RootElement.GetProperty("frames").GetProperty("accept").EnumerateArray())
        {
            if (!testCase.TryGetProperty("egressCode", out var code))
            {
                continue;
            }
            refusals++;
            var name = testCase.GetProperty("name").GetString();
            var harness = new Harness("::/0");
            harness.Runtime.HandleFrameFrom(7, ConsumerMesh, Convert.FromHexString(testCase.GetProperty("frameHex").GetString()!), Epoch);
            Assert.True(harness.RejectCodes().SequenceEqual([code.GetString()!]),
                $"{name}: refused with [{string.Join(",", harness.RejectCodes())}], want {code.GetString()}");
            Assert.True(harness.DialCount == 0, $"{name}: a refused packet was dialled");
        }
        Assert.True(refusals > 0, "the vector carried no frame the runtime refuses");
    }

    /// <summary>The consumer-to-egress frames the runtime does not refuse open a flow to the IPv6 destination.</summary>
    [Fact]
    public void Ipv6VectorFramesOpenFlows()
    {
        using var vector = ReadIpv6Vector();
        var opened = 0;
        foreach (var testCase in vector.RootElement.GetProperty("frames").GetProperty("accept").EnumerateArray())
        {
            if (testCase.GetProperty("direction").GetString() != "consumer-to-egress" || testCase.TryGetProperty("egressCode", out _))
            {
                continue;
            }
            opened++;
            var name = testCase.GetProperty("name").GetString();
            var harness = new Harness("2001:db8:1::/48");
            try
            {
                harness.Runtime.HandleFrameFrom(7, ConsumerMesh, Convert.FromHexString(testCase.GetProperty("frameHex").GetString()!), Epoch);
                Assert.True(harness.Runtime.FlowCount == 1, $"{name}: no flow opened");
                Assert.Equal(
                    [$"{testCase.GetProperty("innerDestinationIp").GetString()}:{testCase.GetProperty("innerDestinationPort").GetInt32()}"],
                    harness.Dialed);
                Assert.Empty(harness.RejectCodes());
            }
            finally
            {
                harness.Runtime.Shutdown(Epoch);
            }
        }
        Assert.True(opened > 0, "the vector carried no consumer-to-egress frame to open");
    }

    /// <summary>
    /// The returning SYN-ACK in the vector is exactly what the codec writes for the same segment: header
    /// fields, hop limit and the checksum over the RFC 8200 pseudo-header.
    /// </summary>
    [Fact]
    public void Ipv6SegmentEncodingMatchesSharedVector()
    {
        using var vector = ReadIpv6Vector();
        var checkedAny = false;
        foreach (var testCase in vector.RootElement.GetProperty("frames").GetProperty("accept").EnumerateArray())
        {
            if (testCase.GetProperty("direction").GetString() != "egress-to-consumer")
            {
                continue;
            }
            var frame = PeerEgressFrame.Parse(Convert.FromHexString(testCase.GetProperty("frameHex").GetString()!), ipv6: true);
            Assert.True(frame.Accepted, frame.Code);
            var segment = PeerEgressSegment.Parse6(frame.Body);
            Assert.NotNull(segment);
            Assert.Equal(HexOf(frame.Body), HexOf(PeerEgressSegment.Build(segment!)));
            checkedAny = true;
        }
        Assert.True(checkedAny, "the vector carried no egress-to-consumer frame");
    }

    /// <summary>
    /// The egress resets an unwanted IPv6 segment by the same RFC 793 rule the consumer does, so the
    /// vector's resets are what <see cref="PeerEgressSegment.BuildReset"/> writes too.
    /// </summary>
    [Fact]
    public void Ipv6ResetMatchesSharedVector()
    {
        using var vector = ReadIpv6Vector();
        var cases = vector.RootElement.GetProperty("failure").GetProperty("resetOnPacket").GetProperty("cases")
            .EnumerateArray().ToList();
        Assert.NotEmpty(cases);
        foreach (var testCase in cases)
        {
            var segment = PeerEgressSegment.Parse6(Convert.FromHexString(testCase.GetProperty("packetHex").GetString()!));
            Assert.NotNull(segment);
            Assert.Equal(testCase.GetProperty("expect").GetProperty("packetHex").GetString(),
                HexOf(PeerEgressSegment.BuildReset(segment!)));
        }
    }

    [Fact]
    public void Ipv6DatagramRoundTrips()
    {
        var original = new PeerEgressDatagram.Datagram(0, 0, 51000, 53, "query"u8.ToArray(),
            Ipv6: true, SourceIp6: Consumer6(), DestinationIp6: Address6("2001:db8:1::35"));
        var packet = PeerEgressDatagram.Build(original);
        Assert.Equal(0x60000000u, BinaryPrimitives.ReadUInt32BigEndian(packet));
        Assert.Equal(PeerEgressIpv6.HopLimit, packet[7]);
        var parsed = PeerEgressDatagram.Parse6(packet);
        Assert.NotNull(parsed);
        Assert.Equal(original.SourceIp6, parsed!.SourceIp6);
        Assert.Equal(original.DestinationIp6, parsed.DestinationIp6);
        Assert.Equal(original.SourcePort, parsed.SourcePort);
        Assert.Equal(original.DestinationPort, parsed.DestinationPort);
        Assert.Equal("query"u8.ToArray(), parsed.Payload);
        // An IPv4 parser does not read it, nor an IPv6 one an IPv4 datagram.
        Assert.Null(PeerEgressDatagram.Parse(packet));
        Assert.Null(PeerEgressDatagram.Parse6(PeerEgressDatagram.Build(original with { Ipv6 = false })));

        // IPv6 has no optional UDP checksum.
        var zeroed = (byte[])packet.Clone();
        zeroed[PeerEgressIpv6.HeaderBytes + 6] = 0;
        zeroed[PeerEgressIpv6.HeaderBytes + 7] = 0;
        Assert.Null(PeerEgressDatagram.Parse6(zeroed));
        var damaged = (byte[])packet.Clone();
        damaged[^1] ^= 0xFF;
        Assert.Null(PeerEgressDatagram.Parse6(damaged));
    }

    /// <summary>
    /// A consumer speaks only for its own derived address. A packet from any other source -- another
    /// device's derived address, an address outside the prefix -- is dropped before anything is judged,
    /// opened or answered, and so is every IPv6 packet from a session whose mesh address is unknown.
    /// </summary>
    [Theory]
    [InlineData("another device's address")]
    [InlineData("an address outside the prefix")]
    [InlineData("a session without a mesh address")]
    [InlineData("a datagram from another device")]
    public void Ipv6DropsAForgedSource(string variant)
    {
        var harness = new Harness("::/0");
        var syn = Syn6(40000, "2001:db8:1::c8", 443);
        switch (variant)
        {
            case "another device's address":
                harness.Runtime.HandleFrameFrom(7, ConsumerMesh, FrameFor(PeerEgressSegment.Build(
                    syn with { SourceIp6 = PeerEgressMeshAddress.Derive(Address("100.96.0.2")) })), Epoch);
                break;
            case "an address outside the prefix":
                harness.Runtime.HandleFrameFrom(7, ConsumerMesh, FrameFor(PeerEgressSegment.Build(
                    syn with { SourceIp6 = Address6("2001:db8:ffff::1") })), Epoch);
                break;
            case "a session without a mesh address":
                harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(syn)), Epoch);
                break;
            case "a datagram from another device":
                harness.Runtime.HandleFrameFrom(9, "100.96.0.9", FrameFor(PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(
                    0, 0, 51000, 53, "query"u8.ToArray(), Ipv6: true, SourceIp6: syn.SourceIp6,
                    DestinationIp6: syn.DestinationIp6))), Epoch);
                break;
        }
        Assert.True(harness.DialCount == 0 && harness.Runtime.FlowCount == 0, "a packet with a forged source opened a flow");
        Assert.True(harness.FrameCount == 0, $"a packet with a forged source was answered with {harness.FrameCount} frames");
        Assert.Empty(harness.Runtime.StatusSnapshot().Refused);
    }

    /// <summary>The same SYN from the right address opens, so the drops above are the source and nothing else.</summary>
    [Fact]
    public void Ipv6OpensFromTheConsumersOwnAddress()
    {
        var harness = new Harness("::/0");
        try
        {
            harness.Runtime.HandleFrameFrom(7, ConsumerMesh, FrameFor(PeerEgressSegment.Build(Syn6(40000, "2001:db8:1::c8", 443))), Epoch);
            Assert.Equal(["2001:db8:1::c8:443"], harness.Dialed);
            var synAck = Assert.Single(harness.Segments6());
            Assert.True(synAck.Has(PeerEgressSegment.FlagSyn) && synAck.Has(PeerEgressSegment.FlagAck));
            // The path MTU the stack starts from is 1280; an IPv6 header and a TCP header come out of it.
            Assert.Equal(PeerEgressRuntime.DefaultPathMtu - PeerEgressIpv6.HeaderBytes - PeerEgressSegment.TcpMinHeaderBytes,
                synAck.Mss);
            AssertReturnHeader(harness.Packets6()[0], Address6("2001:db8:1::c8"), Consumer6());
        }
        finally
        {
            harness.Runtime.Shutdown(Epoch);
        }
    }

    /// <summary>
    /// The derived prefix is the mesh to IPv6: a destination inside it is refused the way a mesh IPv4
    /// destination is, however broad the policy, and the consumer gets an IPv6 reset and a flow-reject
    /// written in IPv6.
    /// </summary>
    [Fact]
    public void Ipv6RefusesAMeshDestination()
    {
        var harness = new Harness("::/0");
        harness.Runtime.ApplyPolicy(Policy("::/0", "fc00::/7") with { Scope = PeerEgressAuthorization.ScopeLan },
            PeerEgressContext.Default, Epoch);
        const string destination = "fd53:7065:6375:7300::6460:2";
        harness.Runtime.HandleFrameFrom(7, ConsumerMesh, FrameFor(PeerEgressSegment.Build(Syn6(40000, destination, 22))), Epoch);

        Assert.True(harness.DialCount == 0, "a mesh destination was dialled");
        var control = Assert.Single(harness.Controls());
        Assert.Equal(PeerEgressCodes.ForbiddenDestination, control.Code);
        Assert.Equal(ConsumerAddress6, control.SourceIp);
        Assert.Equal(destination, control.DestinationIp);
        Assert.Equal("tcp", control.Protocol);
        Assert.Equal(40000, control.SourcePort);
        Assert.Equal(22, control.DestinationPort);
        var reset = Assert.Single(harness.Segments6());
        Assert.True(reset.Has(PeerEgressSegment.FlagRst));
        AssertReturnHeader(harness.Packets6()[0], Address6(destination), Consumer6());
    }

    /// <summary>ICMPv6 is refused the way ICMP over IPv4 is, before the source or anything else is looked at.</summary>
    [Fact]
    public void Ipv6RefusesIcmpv6()
    {
        var harness = new Harness("::/0");
        var packet = new byte[PeerEgressIpv6.HeaderBytes + 8];
        PeerEgressIpv6.WriteHeader(packet, PeerEgressIpv6.NextHeaderIcmp, 8, Consumer6(), Address6("2001:db8:1::c8"));
        packet[PeerEgressIpv6.HeaderBytes] = 128; // echo request
        harness.Runtime.HandleFrameFrom(7, ConsumerMesh, FrameFor(packet), Epoch);

        Assert.True(harness.DialCount == 0, "ICMPv6 opened a socket");
        Assert.Equal([PeerEgressCodes.ProtocolDenied], harness.RejectCodes());
    }

    /// <summary>A stray segment for an IPv6 flow that was never opened gets an IPv6 reset.</summary>
    [Fact]
    public void Ipv6ResetsSegmentsForUnknownFlows()
    {
        var harness = new Harness("::/0");
        var stray = Syn6(40000, "2001:db8:1::c8", 443) with
        {
            Flags = PeerEgressSegment.FlagAck, Seq = 5000, Ack = 9000, Mss = 0, Payload = "stale"u8.ToArray(),
        };
        harness.Runtime.HandleFrameFrom(7, ConsumerMesh, FrameFor(PeerEgressSegment.Build(stray)), Epoch);

        Assert.True(harness.DialCount == 0, "a stray segment opened a socket");
        var reset = Assert.Single(harness.Segments6());
        Assert.True(reset.Has(PeerEgressSegment.FlagRst));
        Assert.Equal(9000u, reset.Seq);
    }

    /// <summary>
    /// flow-purge names IPv6 prefixes as well, and a prefix closes only flows of its own family. A policy
    /// push that withdraws the IPv6 rule closes the IPv6 flow with a flow-reject written in IPv6.
    /// </summary>
    [Fact]
    public void Ipv6FlowsArePurgedAndRevokedByFamily()
    {
        var harness = new Harness("203.0.113.0/24", "2001:db8:1::/48");
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(Syn("100.96.0.1", 40000, "203.0.113.10", 443))), Epoch);
        harness.Runtime.HandleFrameFrom(7, ConsumerMesh, FrameFor(PeerEgressSegment.Build(Syn6(40001, "2001:db8:1::c8", 443))), Epoch);
        Assert.Equal(2, harness.Runtime.FlowCount);

        // 0.0.0.0/0 holds no IPv6 flow, and an IPv6 prefix that does not cover it none either.
        harness.Runtime.HandleFrame(7, PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false,
            PeerEgressFrame.EncodeControl(PeerEgressFrame.Control.FlowPurge(["0.0.0.0/0", "2001:db8:2::/48"], ""))), Epoch);
        Assert.Equal(1, harness.Runtime.FlowCount);
        Assert.True(harness.Socket(0).IsClosed, "an IPv4 purge missed the IPv4 flow");
        Assert.False(harness.Socket(1).IsClosed, "an IPv4 purge reached the IPv6 flow");

        harness.Runtime.ApplyPolicy(Policy("203.0.113.0/24"), PeerEgressContext.Default, Epoch);
        Assert.Equal(0, harness.Runtime.FlowCount);
        Assert.True(harness.Socket(1).IsClosed, "withdrawing the IPv6 rule left the IPv6 flow open");
        var revoked = Assert.Single(harness.Controls(), control => control.Code == PeerEgressCodes.DestinationDenied);
        Assert.Equal(ConsumerAddress6, revoked.SourceIp);
        Assert.Equal("2001:db8:1::c8", revoked.DestinationIp);
        Assert.Equal(40001, revoked.SourcePort);

        // An IPv6 purge reaches an IPv6 flow, and only the flows of the consumer that sent it.
        harness.Runtime.ApplyPolicy(Policy("2001:db8:1::/48"), PeerEgressContext.Default, Epoch);
        harness.Runtime.HandleFrameFrom(7, ConsumerMesh, FrameFor(PeerEgressSegment.Build(Syn6(40002, "2001:db8:1::c9", 443))), Epoch);
        Assert.Equal(1, harness.Runtime.FlowCount);
        var purge = PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false,
            PeerEgressFrame.EncodeControl(PeerEgressFrame.Control.FlowPurge(["2001:db8:1::c9"], "")));
        harness.Runtime.HandleFrame(9, purge, Epoch);
        Assert.Equal(1, harness.Runtime.FlowCount);
        harness.Runtime.HandleFrame(7, purge, Epoch);
        Assert.Equal(0, harness.Runtime.FlowCount);
    }
}
