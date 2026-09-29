using Specus.Client.PeerMesh;
using Xunit;

namespace Specus.Client.Tests;

public sealed class PeerEgressSendQueueTests
{
    [Fact]
    public void SegmentsAreTakenAcrossTheChunksTheyArrivedIn()
    {
        var queue = new SendQueue();
        queue.Add([1, 2, 3]);
        queue.Add([]);
        queue.Add([4, 5]);
        queue.Add([6, 7, 8, 9]);
        Assert.Equal(9, queue.Count);

        // A peek leaves everything in place, so a refused segment is sent again unchanged.
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, queue.Peek(4));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, queue.Peek(4));

        queue.Skip(2);
        Assert.Equal(7, queue.Count);
        Assert.Equal(new byte[] { 3, 4, 5, 6, 7 }, queue.Peek(5));

        queue.Skip(3);
        Assert.Equal(new byte[] { 6 }, queue.Peek(1));
        queue.Skip(4);
        Assert.Equal(0, queue.Count);

        queue.Add([10]);
        Assert.Equal(new byte[] { 10 }, queue.Peek(1));
        queue.Clear();
        Assert.Equal(0, queue.Count);
    }
}
