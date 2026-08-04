using Specus.Client.Control;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;

namespace Specus.Client.Tests;

public class FrameWriterTests
{
    [Fact]
    public async Task WriteAsyncRaisesPacketWrittenAfterSuccessfulFlush()
    {
        await using var stream = new MemoryStream();
        await using var writer = new FrameWriter(stream);
        var writes = 0;
        writer.PacketWritten += () => writes++;

        await writer.WriteAsync(new HeartbeatRequestPacket(), CancellationToken.None);

        Assert.Equal(1, writes);
        Assert.True(stream.Length > 0);
    }

    [Fact]
    public void StreamQueueDequeuesOneFramePerStreamTurn()
    {
        var queue = new StreamRoundRobinQueue<string>(32, static value => value.Length);
        Assert.Equal(StreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(1, "1a"));
        Assert.Equal(StreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(1, "1b"));
        Assert.Equal(StreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(2, "2a"));
        Assert.Equal(StreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(2, "2b"));

        var actual = new List<string>();
        while (queue.TryDequeue(out var value))
        {
            actual.Add(value!);
        }

        Assert.Equal(["1a", "2a", "1b", "2b"], actual);
    }

    [Fact]
    public void StreamQueueEnforcesPerStreamCapacityWithoutBlockingOtherStreams()
    {
        var queue = new StreamRoundRobinQueue<string>(4, static value => value.Length);
        Assert.Equal(StreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(1, "1234"));
        Assert.Equal(StreamQueueEnqueueResult.CapacityExceeded, queue.TryEnqueue(1, "5"));
        Assert.Equal(StreamQueueEnqueueResult.Enqueued, queue.TryEnqueue(2, "abcd"));
    }

    [Fact]
    public async Task NatDataAndFinUseTheQueuedWriterPathInOrder()
    {
        await using var stream = new MemoryStream();
        await using var writer = new FrameWriter(stream);

        await writer.WriteAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = 7,
            Data = [1, 2, 3],
        }, CancellationToken.None);
        await writer.WriteAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = 7,
        }, CancellationToken.None);

        var bytes = stream.ToArray();
        Assert.True(PacketCodec.TryDecode(bytes, out var first, out var consumed));
        Assert.Equal(NatMessageType.Data, Assert.IsType<NatMessagePacket>(first).NatMessageType);
        Assert.True(PacketCodec.TryDecode(bytes.AsSpan(consumed), out var second, out var next));
        Assert.Equal(NatMessageType.Fin, Assert.IsType<NatMessagePacket>(second).NatMessageType);
        Assert.Equal(bytes.Length, consumed + next);
    }
}
