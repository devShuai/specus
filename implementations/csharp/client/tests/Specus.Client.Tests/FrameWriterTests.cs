using Specus.Client.Control;
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
}
