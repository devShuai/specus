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

    [Fact]
    public async Task DiscardedBodyNeverFillsTheQueueOrEarnsCreditButStillCountsAgainstTheWindow()
    {
        var writer = new CapturingFrameWriter();
        await using var stream = CreateStream(writer);
        stream.DiscardResponseBody();

        Assert.True(stream.OnResponseHead(new Dictionary<string, object?> { ["statusCode"] = 200 }));
        for (var i = 0; i < 100; i++)
        {
            Assert.True(stream.OnResponseData(new byte[1024]));
        }
        Assert.False(stream.OnResponseData(new byte[checked((int)StreamSendWindow.InitialBytes)]));
        Assert.False(stream.ResponseEnded);
        Assert.True(stream.OnResponseEnd(null));
        Assert.True(stream.ResponseEnded);

        var head = await stream.WaitResponseHeadAsync(CancellationToken.None);
        Assert.Equal(200, Convert.ToInt32(head["statusCode"]));
        Assert.Empty(writer.Packets);
    }

    [Fact]
    public async Task ResetCarriesTheFailureAndALostLinkIsNotAClientReset()
    {
        await using var reset = CreateStream(new CapturingFrameWriter());
        Assert.True(reset.OnReset(26, "dial tcp 10.0.0.1:80: refused", "connect-refused"));
        var error = await Assert.ThrowsAsync<HttpStreamResetException>(
            async () => await reset.WaitResponseHeadAsync(CancellationToken.None));
        Assert.Equal("connect-refused", error.Failure);
        Assert.False(error.LinkLost);
        Assert.DoesNotContain("10.0.0.1", error.Message, StringComparison.Ordinal);

        await using var lost = CreateStream(new CapturingFrameWriter());
        lost.OnLinkLost();
        var lostError = await Assert.ThrowsAsync<HttpStreamResetException>(
            async () => await lost.WaitResponseHeadAsync(CancellationToken.None));
        Assert.True(lostError.LinkLost);
        Assert.Null(lostError.Failure);
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
