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
