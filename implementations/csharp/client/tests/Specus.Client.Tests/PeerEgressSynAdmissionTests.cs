using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

public class PeerEgressSynAdmissionTests
{
    [Fact]
    public void AdmissionPreservesSequenceMssAndHandshake()
    {
        Assert.True(Ipv4Cidr.TryParseAddress("100.96.0.1", out var source));
        Assert.True(Ipv4Cidr.TryParseAddress("203.0.113.10", out var target));
        var syn = new PeerEgressSegment.Segment(source, target, 40000, 443, 1000, 0,
            PeerEgressSegment.FlagSyn, 65535, 1360, []);
        var admit = false;
        var attempts = 0;
        List<PeerEgressSegment.Segment> sent = [];
        var output = new PeerEgressTcpConnection.Output();
        var conn = PeerEgressTcpConnection.Accept(syn, uint.MaxValue, 1280, 60_000, 0, output, packet =>
        {
            attempts++;
            if (!admit) return false;
            var segment = PeerEgressSegment.Parse(packet);
            Assert.NotNull(segment);
            sent.Add(segment!);
            return true;
        });
        Assert.Empty(output.Segments);
        Assert.True(conn.SendBlocked);
        conn.OnAppData([1, 2, 3], 0);
        var forged = syn with { Flags = PeerEgressSegment.FlagAck, Seq = syn.Seq + 1, Ack = uint.MaxValue };
        conn.OnSegment(forged, 0);
        for (var tick = 1; tick <= 10; tick++) conn.OnTick(tick);
        Assert.Equal(PeerEgressTcpConnection.State.SynReceived, conn.CurrentState);
        Assert.Equal(11, attempts);
        Assert.Empty(sent);
        admit = true;
        conn.OnTick(2000);
        var synAck = Assert.Single(sent);
        Assert.Equal(uint.MaxValue, synAck.Seq);
        Assert.Equal(1240, synAck.Mss);
        Assert.Equal(PeerEgressSegment.FlagSyn | PeerEgressSegment.FlagAck, synAck.Flags);
        conn.OnTick(2999);
        Assert.Single(sent);
        conn.OnSegment(forged with { Ack = 0 }, 3000);
        Assert.Equal(PeerEgressTcpConnection.State.Established, conn.CurrentState);
        Assert.Equal(2, sent.Count);
        Assert.Equal(0u, sent[1].Seq);
        Assert.Equal(new byte[]{1, 2, 3}, sent[1].Payload);
    }
}
