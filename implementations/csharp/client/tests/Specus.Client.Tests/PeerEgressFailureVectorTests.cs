using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Binds what the consumer writes back into the TUN to <c>peer-egress-failure-v1.json</c>.
/// </summary>
/// <remarks>
/// Three runtimes that reset a flow at different sequence numbers would leave the application
/// hanging on one of them: a reset a stack does not accept is a reset that was not sent.
/// </remarks>
public class PeerEgressFailureVectorTests
{
    private const long Epoch = 1_800_000_000_000L;

    private static JsonDocument Vector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-failure-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-failure-v1.json");
    }

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }

    private static string Hex(byte[]? packet) =>
        packet is null ? "" : Convert.ToHexString(packet).ToLowerInvariant();

    /// <summary>
    /// A flow the consumer closes is reset from what it remembered. Driven through the consumer:
    /// the application's last segment carries the numbers, the egress goes offline, and the reset
    /// that reaches the TUN has to be the vector's bytes.
    /// </summary>
    [Fact]
    public void ResetsOnPurgeMatchTheSharedVector()
    {
        using var vector = Vector();
        var cases = vector.RootElement.GetProperty("resetOnPurge").GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "no purge cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var toTun = new List<byte[]>();
            var consumer = new PeerEgressConsumer((_, _) => true, toTun.Add);
            var consumerIp = testCase.GetProperty("consumerIp").GetString()!;
            consumer.Configure([new PeerEgressRule { Match = "203.0.113.0/24", Action = "egress", EgressClientId = 2L }],
                PeerEgressRules.DefaultMeshCidr, consumerIp, Epoch);
            consumer.SetEgressOnline(2L, true, Epoch);
            // A segment with ACK and no payload leaves the application's next sequence at its own
            // sequence, and its acknowledgement where the case says.
            consumer.HandleOutbound(PeerEgressSegment.Build(new PeerEgressSegment.Segment(
                Address(consumerIp), Address(testCase.GetProperty("remoteIp").GetString()!),
                (ushort)testCase.GetProperty("consumerPort").GetInt32(), (ushort)testCase.GetProperty("remotePort").GetInt32(),
                testCase.GetProperty("appSeqNext").GetUInt32(), testCase.GetProperty("appAck").GetUInt32(),
                PeerEgressSegment.FlagAck, 65535, 0, [])), Epoch);
            toTun.Clear();

            consumer.SetEgressOnline(2L, false, Epoch);

            Assert.True(toTun.Count == 1, $"{name}: {toTun.Count} packets written");
            Assert.True(testCase.GetProperty("expect").GetProperty("packetHex").GetString() == Hex(toTun[0]), name);
        }
    }

    [Fact]
    public void ResetsOnPacketMatchTheSharedVector()
    {
        using var vector = Vector();
        var cases = vector.RootElement.GetProperty("resetOnPacket").GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "no packet cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            var packet = Convert.FromHexString(testCase.GetProperty("packetHex").GetString()!);
            var answer = PeerEgressConsumer.FailurePacket(packet, PeerEgressSegment.Ipv4ProtocolTcp);
            Assert.True(testCase.GetProperty("expect").GetProperty("packetHex").GetString() == Hex(answer),
                testCase.GetProperty("name").GetString());
        }
    }

    [Fact]
    public void UnreachablesOnDatagramMatchTheSharedVector()
    {
        using var vector = Vector();
        var cases = vector.RootElement.GetProperty("unreachableOnDatagram").GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "no datagram cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            var packet = Convert.FromHexString(testCase.GetProperty("packetHex").GetString()!);
            var answer = PeerEgressConsumer.FailurePacket(packet, PeerEgressDatagram.Ipv4ProtocolUdp);
            Assert.True(testCase.GetProperty("expect").GetProperty("packetHex").GetString() == Hex(answer),
                testCase.GetProperty("name").GetString());
        }
    }
}
