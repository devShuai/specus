using Specus.Protocol.Flow;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;
using Specus.Server.Nat;
using Specus.Server.Networking;

namespace Specus.IntegrationTests;

public sealed class HttpSpecusStreamTests
{
    [Fact]
    public async Task SaturatedQueueRejectsDataWithoutDroppingOrLeakingCredit()
    {
        var writer = new CapturingFrameWriter();
        await using var stream = CreateStream(writer);

        Assert.True(stream.OnResponseHead(new Dictionary<string, object?>
        {
            ["statusCode"] = 200,
        }));
        for (var value = 0; value < 31; value++)
        {
            Assert.True(stream.OnResponseData([(byte)value]));
        }
        Assert.False(stream.OnResponseData([0xff]));

        var head = await stream.WaitResponseHeadAsync(CancellationToken.None);
        Assert.Equal(200, Convert.ToInt32(head["statusCode"]));
        for (var value = 0; value < 31; value++)
        {
            var item = await stream.ReadResponseAsync(CancellationToken.None);
            Assert.False(item.End);
            Assert.Equal([(byte)value], Assert.IsType<byte[]>(item.Data));
        }

        await stream.ConsumeResponseAsync(31, CancellationToken.None);
        Assert.True(stream.OnResponseData(new byte[checked((int)StreamSendWindow.InitialBytes)]));
        var credit = Assert.IsType<NatMessagePacket>(Assert.Single(writer.Packets));
        Assert.Equal(Protocol.NatMessageType.WindowUpdate, credit.NatMessageType);
        Assert.Equal(31U, credit.Value);
    }

    [Fact]
    public async Task SaturatedQueueRejectsTerminalEventInsteadOfReportingDroppedSuccess()
    {
        await using var stream = CreateStream(new CapturingFrameWriter());

        Assert.True(stream.OnResponseHead(new Dictionary<string, object?>()));
        for (var value = 0; value < 31; value++)
        {
            Assert.True(stream.OnResponseData([(byte)value]));
        }

        Assert.False(stream.OnResponseEnd(new Dictionary<string, object?>
        {
            ["trailers"] = Array.Empty<string>(),
        }));
    }

    private static HttpSpecusStream CreateStream(IFrameWriter writer)
    {
        var context = new SpecusConnectionContext(
            "http-stream-test",
            null,
            writer,
            CancellationToken.None,
            static () => { },
            new ReadGate(CancellationToken.None),
            new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        return new HttpSpecusStream(context, 7, static (_, _) => { });
    }

    private sealed class CapturingFrameWriter : IFrameWriter
    {
        public List<Packet> Packets { get; } = [];

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            Packets.Add(packet);
            return ValueTask.CompletedTask;
        }
    }
}
