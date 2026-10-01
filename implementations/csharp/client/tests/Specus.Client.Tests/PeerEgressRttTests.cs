using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

public class PeerEgressRttTests
{
    private static PeerEgressSegment.Segment Ack(uint next) => new(
        0x64600001, 0xcb00710a, 40000, 443, 1001, next, PeerEgressSegment.FlagAck, 65535, 0, []);

    private static PeerEgressTcpConnection AfterRetransmittedAck()
    {
        var syn = new PeerEgressSegment.Segment(0x64600001, 0xcb00710a, 40000, 443,
            1000, 0, PeerEgressSegment.FlagSyn, 65535, 1240, []);
        var connection = PeerEgressTcpConnection.Accept(syn, 5000, 1280, 60000, 0,
            new PeerEgressTcpConnection.Output());
        connection.OnSegment(Ack(5001), 10);
        connection.OnAppData([1], 10);
        Assert.Single(connection.OnTick(210).Segments);
        connection.OnSegment(Ack(5002), 210);
        return connection;
    }

    [Fact]
    public void RetransmittedAckDoesNotCollapseBackoff()
    {
        var connection = AfterRetransmittedAck();
        connection.OnAppData([2], 210);
        Assert.Empty(connection.OnTick(410).Segments); // Karn preserves the 400 ms backoff.
        Assert.Single(connection.OnTick(610).Segments);
    }

    /// <summary>
    /// The segments sent alongside a lost one are acknowledged only when its retransmission fills
    /// the hole, so their send-to-ACK time is the retransmission timeout, not the path. Taking them
    /// as round-trip samples made every recovery stretch the next timeout (here 419 ms instead of
    /// the 200 ms floor after one recovery and one clean ACK), and in the lab a flow with 64 KiB
    /// queued went seconds without retransmitting the hole its consumer was waiting for.
    /// </summary>
    [Fact]
    public void TheAckThatFillsAHoleIsNotARoundTripSample()
    {
        var syn = new PeerEgressSegment.Segment(0x64600001, 0xcb00710a, 40000, 443,
            1000, 0, PeerEgressSegment.FlagSyn, 65535, 1240, []);
        var connection = PeerEgressTcpConnection.Accept(syn, 5000, 1280, 60000, 0,
            new PeerEgressTcpConnection.Output());
        connection.OnSegment(Ack(5001), 10); // unambiguous 10 ms sample => 200 ms RTO

        // Four segments in flight; the first is lost and the consumer holds the other three.
        Assert.Equal(4, connection.OnAppData(new byte[4 * 1240], 10).Segments.Count);
        for (var duplicate = 0; duplicate < 3; duplicate++)
        {
            Assert.Empty(connection.OnSegment(Ack(5001), 11).Segments);
        }
        Assert.Single(connection.OnTick(210).Segments); // the hole, resent
        connection.OnSegment(Ack(5001 + (4 * 1240)), 211); // fills the hole: covers all four

        // One clean round trip, then the next loss.
        Assert.Single(connection.OnAppData(new byte[1240], 211).Segments);
        connection.OnSegment(Ack(5001 + (5 * 1240)), 212);
        Assert.Single(connection.OnAppData(new byte[1240], 300).Segments);
        Assert.Empty(connection.OnTick(499).Segments); // not before the RTO
        Assert.Single(connection.OnTick(500).Segments); // at the floor, not 419 ms later
    }

    [Fact]
    public void SameMillisecondCleanAckCollapsesBackoff()
    {
        var connection = AfterRetransmittedAck();
        connection.OnAppData([2], 210);
        connection.OnSegment(Ack(5003), 210);
        connection.OnAppData([3], 410);
        Assert.Empty(connection.OnTick(609).Segments);
        Assert.Single(connection.OnTick(610).Segments);
    }
}
