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

        Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseHead(new Dictionary<string, object?>
        {
            ["statusCode"] = 200,
        }));
        for (var value = 0; value < 31; value++)
        {
            Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseData([(byte)value]));
        }
        Assert.Equal(HttpStreamIngestResult.QueueFull, stream.OnResponseData([0xff]));

        var head = await stream.WaitResponseHeadAsync(CancellationToken.None);
        Assert.Equal(200, Convert.ToInt32(head["statusCode"]));
        for (var value = 0; value < 31; value++)
        {
            var item = await stream.ReadResponseAsync(CancellationToken.None);
            Assert.False(item.End);
            Assert.Equal([(byte)value], Assert.IsType<byte[]>(item.Data));
        }

        await stream.ConsumeResponseAsync(31, CancellationToken.None);
        Assert.Equal(HttpStreamIngestResult.Accepted,
            stream.OnResponseData(new byte[checked((int)StreamSendWindow.InitialBytes)]));
        var credit = Assert.IsType<NatMessagePacket>(Assert.Single(writer.Packets));
        Assert.Equal(Protocol.NatMessageType.WindowUpdate, credit.NatMessageType);
        Assert.Equal(31U, credit.Value);
    }

    [Fact]
    public async Task SaturatedQueueRejectsTerminalEventInsteadOfReportingDroppedSuccess()
    {
        await using var stream = CreateStream(new CapturingFrameWriter());

        Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseHead(new Dictionary<string, object?>()));
        for (var value = 0; value < 31; value++)
        {
            Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseData([(byte)value]));
        }

        Assert.Equal(HttpStreamIngestResult.QueueFull, stream.OnResponseEnd(new Dictionary<string, object?>
        {
            ["trailers"] = Array.Empty<string>(),
        }));
        Assert.False(stream.ResponseEnded);
    }

    /// <summary>
    /// The server resets a stream whose reader fell behind: the client gets RST 8 and the reader
    /// meets that reset on its next read, ahead of the events still queued, as it would a client RST.
    /// </summary>
    [Fact]
    public async Task OverflowResetReachesTheClientAndTheReaderAheadOfTheQueue()
    {
        var writer = new CapturingFrameWriter();
        await using var stream = CreateStream(writer);
        FillQueue(stream);
        Assert.Equal(HttpStreamIngestResult.QueueFull, stream.OnResponseData([0xff]));

        await stream.ResetOverflowAsync(8, "HTTP response queue exceeded", CancellationToken.None);
        await stream.ResetOverflowAsync(8, "HTTP response queue exceeded", CancellationToken.None);

        var reset = Assert.IsType<NatMessagePacket>(Assert.Single(writer.Packets));
        Assert.Equal(Protocol.NatMessageType.Rst, reset.NatMessageType);
        Assert.Equal(8U, reset.Value);
        var error = await Assert.ThrowsAsync<HttpStreamResetException>(
            async () => await stream.WaitResponseHeadAsync(CancellationToken.None));
        Assert.Equal(8U, error.Code);
        Assert.False(error.LinkLost);
        await Assert.ThrowsAsync<HttpStreamResetException>(
            async () => await stream.ReadResponseAsync(CancellationToken.None));
        Assert.Equal(HttpStreamIngestResult.Closed, stream.OnResponseData([0xff]));
    }

    [Fact]
    public async Task ClientResetOrLostLinkOnAFullQueueStillReachesTheReader()
    {
        await using var reset = CreateStream(new CapturingFrameWriter());
        FillQueue(reset);
        reset.OnReset(26, "upstream reset", "connect-refused");
        var error = await Assert.ThrowsAsync<HttpStreamResetException>(
            async () => await reset.WaitResponseHeadAsync(CancellationToken.None));
        Assert.Equal(26U, error.Code);
        Assert.Equal("connect-refused", error.Failure);

        await using var lost = CreateStream(new CapturingFrameWriter());
        FillQueue(lost);
        lost.OnLinkLost();
        var lostError = await Assert.ThrowsAsync<HttpStreamResetException>(
            async () => await lost.WaitResponseHeadAsync(CancellationToken.None));
        Assert.True(lostError.LinkLost);
    }

    /// <summary>
    /// Once closed, a stream reports every response frame as late, even one that would break the
    /// state machine of an open stream; the session answers those as it answers a tombstone.
    /// </summary>
    [Fact]
    public async Task ClosedStreamReportsLateFramesAsClosedRatherThanAsViolations()
    {
        var writer = new CapturingFrameWriter();
        await using var stream = CreateStream(writer);
        Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseHead(new Dictionary<string, object?>()));
        await stream.ResetAsync(1, "browser left", CancellationToken.None);

        Assert.Equal(HttpStreamIngestResult.Closed, stream.OnResponseHead(new Dictionary<string, object?>()));
        Assert.Equal(HttpStreamIngestResult.Closed, stream.OnResponseData([1]));
        Assert.Equal(HttpStreamIngestResult.Closed, stream.OnResponseData([]));
        Assert.Equal(HttpStreamIngestResult.Closed,
            stream.OnResponseData(new byte[checked((int)StreamSendWindow.InitialBytes) + 1]));
        Assert.Equal(HttpStreamIngestResult.Closed, stream.OnResponseEnd(null));
        stream.OnReset(1, "late");
        await stream.ResetOverflowAsync(8, "HTTP response queue exceeded", CancellationToken.None);
        Assert.Equal(Protocol.NatMessageType.Rst,
            Assert.IsType<NatMessagePacket>(Assert.Single(writer.Packets)).NatMessageType);
    }

    [Fact]
    public async Task OpenStreamStillRejectsFramesOutOfOrderOrBeyondTheWindow()
    {
        await using var stream = CreateStream(new CapturingFrameWriter());
        Assert.Equal(HttpStreamIngestResult.ProtocolViolation, stream.OnResponseData([1]));
        Assert.Equal(HttpStreamIngestResult.ProtocolViolation, stream.OnResponseEnd(null));
        Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseHead(new Dictionary<string, object?>()));
        Assert.Equal(HttpStreamIngestResult.ProtocolViolation, stream.OnResponseHead(new Dictionary<string, object?>()));
        Assert.Equal(HttpStreamIngestResult.ProtocolViolation, stream.OnResponseData([]));
        Assert.Equal(HttpStreamIngestResult.ProtocolViolation,
            stream.OnResponseData(new byte[checked((int)StreamSendWindow.InitialBytes) + 1]));
        Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseEnd(null));
        Assert.Equal(HttpStreamIngestResult.ProtocolViolation, stream.OnResponseData([1]));
        Assert.Equal(HttpStreamIngestResult.ProtocolViolation, stream.OnResponseEnd(null));
    }

    [Fact]
    public async Task DiscardedBodyNeverFillsTheQueueOrEarnsCreditButStillCountsAgainstTheWindow()
    {
        var writer = new CapturingFrameWriter();
        await using var stream = CreateStream(writer, discardResponseBody: true);

        Assert.Equal(HttpStreamIngestResult.Accepted,
            stream.OnResponseHead(new Dictionary<string, object?> { ["statusCode"] = 200 }));
        for (var i = 0; i < 100; i++)
        {
            Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseData(new byte[1024]));
        }
        Assert.Equal(HttpStreamIngestResult.ProtocolViolation,
            stream.OnResponseData(new byte[checked((int)StreamSendWindow.InitialBytes)]));
        Assert.False(stream.ResponseEnded);
        Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseEnd(null));
        Assert.True(stream.ResponseEnded);

        var head = await stream.WaitResponseHeadAsync(CancellationToken.None);
        Assert.Equal(200, Convert.ToInt32(head["statusCode"]));
        Assert.Empty(writer.Packets);
    }

    [Fact]
    public async Task ResetCarriesTheFailureAndALostLinkIsNotAClientReset()
    {
        await using var reset = CreateStream(new CapturingFrameWriter());
        reset.OnReset(26, "dial tcp 10.0.0.1:80: refused", "connect-refused");
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

    /// <summary>Queues the response head and 31 DATA events: the 32 the event queue holds.</summary>
    private static void FillQueue(HttpSpecusStream stream)
    {
        Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseHead(new Dictionary<string, object?>()));
        for (var value = 0; value < 31; value++)
        {
            Assert.Equal(HttpStreamIngestResult.Accepted, stream.OnResponseData([(byte)value]));
        }
    }

    private static HttpSpecusStream CreateStream(IFrameWriter writer, bool discardResponseBody = false)
    {
        var context = new SpecusConnectionContext(
            "http-stream-test",
            null,
            writer,
            CancellationToken.None,
            static () => { },
            new ReadGate(CancellationToken.None),
            new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        return new HttpSpecusStream(context, 7, static (_, _) => { }, discardResponseBody);
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
