using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

public class PeerEgressQueueAdmissionTests
{
    private static PeerEgressTcpConnection Connection()
    {
        var syn = new PeerEgressSegment.Segment(0x64600001, 0xcb00710a, 40000, 443,
            1000, 0, PeerEgressSegment.FlagSyn, 65535, 1240, []);
        var connection = PeerEgressTcpConnection.Accept(syn, 5000, 1280, 60000, 0,
            new PeerEgressTcpConnection.Output());
        connection.OnSegment(syn with { Seq = 1001, Ack = 5001, Flags = PeerEgressSegment.FlagAck }, 0);
        return connection;
    }

    [Fact]
    public void RejectedDataAndFinAreRetainedUntilQueueRecovery()
    {
        var connection = Connection();
        connection.TryTransmit = _ => false;
        connection.OnAppData([1, 2, 3], 0);
        connection.OnAppClose(0);
        for (var i = 1; i <= 10; i++)
        {
            connection.OnTick(i * 1000);
            Assert.Equal(PeerEgressTcpConnection.State.Established, connection.CurrentState);
        }
        var sent = new List<PeerEgressSegment.Segment>();
        connection.TryTransmit = packet => { sent.Add(PeerEgressSegment.Parse(packet)!); return true; };
        connection.OnTick(10000);
        Assert.Equal(2, sent.Count);
        Assert.Equal(5001u, sent[0].Seq);
        Assert.Equal(new byte[] { 1, 2, 3 }, sent[0].Payload);
        Assert.Equal(5004u, sent[1].Seq);
        Assert.True(sent[1].Has(PeerEgressSegment.FlagFin));
    }

    [Fact]
    public void RejectedRetransmissionsDoNotConsumeRetryBudget()
    {
        var connection = Connection();
        connection.OnAppData([1, 2, 3], 0);
        connection.TryTransmit = _ => false;
        for (var i = 1; i <= 10; i++) { connection.OnTick(i * 1000); }
        var sent = new List<PeerEgressSegment.Segment>();
        connection.TryTransmit = packet => { sent.Add(PeerEgressSegment.Parse(packet)!); return true; };
        connection.OnTick(10000);
        Assert.Equal(PeerEgressTcpConnection.State.Established, connection.CurrentState);
        Assert.Single(sent);
        Assert.Equal(5001u, sent[0].Seq);
        sent.Clear();
        connection.OnTick(12000);
        Assert.Single(sent);
    }
}
