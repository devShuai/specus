using Specus.Server.ControlChannel;

namespace Specus.IntegrationTests;

public sealed class ConnectionStreamRoundRobinQueueTests
{
    [Fact]
    public void DequeuesOneFramePerReadyStreamTurn()
    {
        var queue = new ConnectionStreamRoundRobinQueue<string>(32, static value => value.Length);
        Assert.Equal(ConnectionStreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(1, "1a"));
        Assert.Equal(ConnectionStreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(1, "1b"));
        Assert.Equal(ConnectionStreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(2, "2a"));
        Assert.Equal(ConnectionStreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(2, "2b"));

        var actual = new List<string>();
        while (queue.TryDequeue(out var value))
        {
            actual.Add(value!);
        }

        Assert.Equal(["1a", "2a", "1b", "2b"], actual);
    }

    [Fact]
    public void EnforcesCapacityPerStream()
    {
        var queue = new ConnectionStreamRoundRobinQueue<string>(4, static value => value.Length);
        Assert.Equal(ConnectionStreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(1, "1234"));
        Assert.Equal(ConnectionStreamQueueEnqueueResult.CapacityExceeded, queue.TryEnqueue(1, "5"));
        Assert.Equal(ConnectionStreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(2, "abcd"));
    }
}
