using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Specus.Client.PeerMesh;
using Datagram = Specus.Client.PeerMesh.PeerEgressDatagram.Datagram;

namespace Specus.Client.Tests;

/// <summary>The UDP datagram codec, checked against the shared frame vector as well as against itself.</summary>
public class PeerEgressDatagramTests
{
    private const int Udp = PeerEgressSegment.Ipv4MinHeaderBytes;

    private static uint Address(string dotted)
    {
        uint value = 0;
        foreach (var part in dotted.Split('.'))
        {
            value = (value << 8) | byte.Parse(part);
        }
        return value;
    }

    private static Datagram Sample(byte[] payload) =>
        new(Address("100.96.0.1"), Address("203.0.113.53"), 51000, 53, payload);

    private static int ReadShort(byte[] packet, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));

    private static void WriteShort(byte[] packet, int offset, int value) =>
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset, 2), (ushort)value);

    [Fact]
    public void DatagramRoundTrips()
    {
        var original = Sample(Encoding.UTF8.GetBytes("specus-egress-datagram"));
        var parsed = PeerEgressDatagram.Parse(PeerEgressDatagram.Build(original));

        Assert.True(parsed is not null, "a datagram we built did not parse");
        Assert.Equal(original.SourceIp, parsed!.SourceIp);
        Assert.Equal(original.DestinationIp, parsed.DestinationIp);
        Assert.Equal(original.SourcePort, parsed.SourcePort);
        Assert.Equal(original.DestinationPort, parsed.DestinationPort);
        Assert.Equal(original.Payload, parsed.Payload);
    }

    /// <summary>
    /// A payload-free datagram is legal UDP and is what several keepalive schemes send, so refusing
    /// it would silently break the flows that rely on it.
    /// </summary>
    [Fact]
    public void EmptyPayloadIsCarried()
    {
        var packet = PeerEgressDatagram.Build(Sample([]));
        var parsed = PeerEgressDatagram.Parse(packet);

        Assert.True(parsed is not null, "an empty datagram was refused");
        Assert.Empty(parsed!.Payload);
        Assert.Equal(PeerEgressDatagram.UdpHeaderBytes, ReadShort(packet, Udp + 4));
    }

    [Fact]
    public void UntrustworthyInputIsRefused()
    {
        var good = PeerEgressDatagram.Build(Sample(Encoding.UTF8.GetBytes("query")));

        var corrupted = (byte[])good.Clone();
        corrupted[Udp + PeerEgressDatagram.UdpHeaderBytes] ^= 0xFF;
        Assert.True(PeerEgressDatagram.Parse(corrupted) is null, "a bad checksum was accepted");

        Assert.True(
            PeerEgressDatagram.Parse(good.AsSpan(0, Udp + 4)) is null,
            "a truncated datagram was accepted");

        // A UDP length shorter than what IPv4 delivered would leave trailing bytes riding along.
        var shortLength = (byte[])good.Clone();
        WriteShort(shortLength, Udp + 4, PeerEgressDatagram.UdpHeaderBytes);
        Assert.True(PeerEgressDatagram.Parse(shortLength) is null, "an understated length was accepted");

        var longLength = (byte[])good.Clone();
        WriteShort(longLength, Udp + 4, 4096);
        Assert.True(PeerEgressDatagram.Parse(longLength) is null, "an overstated length was accepted");

        var tcp = (byte[])good.Clone();
        tcp[9] = PeerEgressSegment.Ipv4ProtocolTcp;
        Assert.True(PeerEgressDatagram.Parse(tcp) is null, "a non-UDP packet was accepted");
    }

    /// <summary>IPv4 lets a sender skip the UDP checksum, and plenty do. Refusing those would drop real traffic.</summary>
    [Fact]
    public void AbsentChecksumIsAccepted()
    {
        var packet = PeerEgressDatagram.Build(Sample(Encoding.UTF8.GetBytes("query")));
        WriteShort(packet, Udp + 6, 0);
        Assert.True(PeerEgressDatagram.Parse(packet) is not null, "a datagram with no checksum was refused");
    }

    /// <summary>
    /// RFC 768 reserves zero to mean "not computed", so a checksum that works out to zero has to go
    /// on the wire as its complement instead. A receiver would otherwise stop verifying that flow.
    /// </summary>
    [Fact]
    public void AComputedZeroChecksumIsSentAsFfff()
    {
        // Searched rather than hand-derived: the payload that sums to zero depends on the addresses
        // and ports, so pinning one here would be a constant nobody could re-derive.
        var found = false;
        for (var candidate = 0; candidate <= 0xFFFF; candidate++)
        {
            var packet = PeerEgressDatagram.Build(Sample([(byte)(candidate >> 8), (byte)candidate]));
            if (ReadShort(packet, Udp + 6) != 0xFFFF)
            {
                continue;
            }
            Assert.True(PeerEgressDatagram.Parse(packet) is not null, "the 0xffff form did not verify");
            found = true;
            break;
        }
        Assert.True(found, "no payload produced the forced form, so the guard went untested");
    }

    /// <summary>
    /// The strongest check available: this packet came out of the vector generator, not out of this
    /// codec, so agreeing on it is agreement between two implementations.
    /// </summary>
    [Fact]
    public void ParsesTheUdpDatagramFromTheSharedFrameVector()
    {
        using var vector = ReadVector("peer-egress-frame-v1.json");
        var innerHex = "";
        var wantSource = 0;
        var wantDestination = 0;
        foreach (var testCase in vector.RootElement.GetProperty("accept").EnumerateArray())
        {
            if (testCase.GetProperty("name").GetString() != "ip-udp-outbound")
            {
                continue;
            }
            innerHex = testCase.GetProperty("innerPacketHex").GetString()!;
            wantSource = testCase.GetProperty("innerSourcePort").GetInt32();
            wantDestination = testCase.GetProperty("innerDestinationPort").GetInt32();
        }
        Assert.False(innerHex.Length == 0, "frame vector no longer carries ip-udp-outbound");

        var parsed = PeerEgressDatagram.Parse(Convert.FromHexString(innerHex));
        Assert.True(parsed is not null, "the vector datagram did not parse");
        Assert.Equal(wantSource, parsed!.SourcePort);
        Assert.Equal(wantDestination, parsed.DestinationPort);
    }

    private static JsonDocument ReadVector(string name)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", name);
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException($"cannot locate {name}");
    }
}
