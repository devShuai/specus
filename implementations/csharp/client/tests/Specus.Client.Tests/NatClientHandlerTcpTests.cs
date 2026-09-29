using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Client.Nat;
using Specus.Protocol;
using Specus.Protocol.Packets;

namespace Specus.Client.Tests;

public sealed class NatClientHandlerTcpTests
{
    [Fact]
    public async Task DataAfterRemoteFinAndDuplicateFinResetOnlyTheStream()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        await using var handler = CreateHandler(writer,
        [
            Mapping(17017, port),
        ]);
        handler.Bind(timeout.Token);

        var accepted = listener.AcceptTcpClientAsync(timeout.Token);
        await handler.HandleAsync(Open(71, 17017));
        using var peer = await accepted;
        await WaitUntilAsync(() => handler.HasTcpStream(71), timeout.Token);

        await handler.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = 71,
        });
        await handler.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = 71,
            Data = [1],
        });
        await handler.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = 71,
        });

        var frames = await ReadFramesAsync(transport, 2, timeout.Token);
        Assert.All(frames, frame => Assert.Equal(NatMessageType.Rst, frame.NatMessageType));

        // A stream error did not poison the NAT handler/data connection.
        await handler.HandleAsync(new NatMessagePacket { NatMessageType = NatMessageType.Keepalive });
    }

    [Theory]
    [InlineData(NatMessageType.Data)]
    [InlineData(NatMessageType.Fin)]
    public async Task UnknownTcpDataOrFinSendsResetAndKeepsDataConnection(NatMessageType type)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        await using var handler = CreateHandler(writer, []);
        handler.Bind(timeout.Token);

        await handler.HandleAsync(new NatMessagePacket
        {
            NatMessageType = type,
            StreamId = 999,
            Data = type == NatMessageType.Data ? [1] : null,
        });
        await handler.HandleAsync(new NatMessagePacket { NatMessageType = NatMessageType.Keepalive });

        var reset = Assert.Single(await ReadFramesAsync(transport, 1, timeout.Token));
        Assert.Equal(NatMessageType.Rst, reset.NatMessageType);
        Assert.Equal(999U, reset.StreamId);
    }

    [Fact]
    public async Task ResetForNeverOpenedStreamRemainsConnectionProtocolViolation()
    {
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        await using var handler = CreateHandler(writer, []);
        handler.Bind(CancellationToken.None);

        await Assert.ThrowsAsync<InvalidDataException>(() => handler.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Rst,
            StreamId = 999,
        }));
    }

    [Fact]
    public async Task TcpDataEndStreamDeliversPayloadBeforeHalfClose()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        await using var handler = CreateHandler(writer, [Mapping(17018, port)]);
        handler.Bind(timeout.Token);

        var accepted = listener.AcceptTcpClientAsync(timeout.Token);
        await handler.HandleAsync(Open(72, 17018));
        using var peer = await accepted;
        await WaitUntilAsync(() => handler.HasTcpStream(72), timeout.Token);

        var payload = "payload-before-fin"u8.ToArray();
        await handler.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = 72,
            Data = payload,
            Flags = NatMessagePacket.FlagEndStream,
        });

        var received = new byte[payload.Length];
        await peer.GetStream().ReadExactlyAsync(received, timeout.Token);
        Assert.Equal(payload, received);
        Assert.Equal(0, await peer.GetStream().ReadAsync(new byte[1], timeout.Token));
    }

    [Fact]
    public async Task ResetWhileTcpDialIsPendingCancelsReservationAndToleratesLateReset()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        static async Task<TcpClient> PendingConnector(
            string address, int port, CancellationToken cancellationToken)
        {
            _ = address;
            _ = port;
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
        await using var handler = CreateHandler(writer, [Mapping(17019, 1)], PendingConnector);
        handler.Bind(timeout.Token);

        await handler.HandleAsync(Open(73, 17019));
        Assert.True(handler.HasPendingStream(73));
        await handler.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Rst,
            StreamId = 73,
        });
        await handler.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Rst,
            StreamId = 73,
        });

        Assert.False(handler.HasPendingStream(73));
        Assert.Equal(0, transport.Length);
    }

    [Fact]
    public async Task FailedTcpDialSendsResetAndReleasesPendingReservation()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        static Task<TcpClient> FailedConnector(
            string address, int port, CancellationToken cancellationToken)
        {
            _ = address;
            _ = port;
            _ = cancellationToken;
            return Task.FromException<TcpClient>(
                new SocketException((int)SocketError.ConnectionRefused));
        }
        await using var handler = CreateHandler(writer, [Mapping(17020, 1)], FailedConnector);
        handler.Bind(timeout.Token);

        await handler.HandleAsync(Open(74, 17020));
        await WaitUntilAsync(() => transport.Length > 0, timeout.Token);

        Assert.False(handler.HasPendingStream(74));
        var reset = Assert.Single(await ReadFramesAsync(transport, 1, timeout.Token));
        Assert.Equal(NatMessageType.Rst, reset.NatMessageType);
        Assert.Equal(74U, reset.StreamId);
    }

    // #77. A DATA that has already missed every live channel must still find its stream if the
    // local dial completes before it looks for the pending one. It used to find neither, answer the
    // server with "DATA for unknown TCP stream", and reset a stream that was up.
    [Fact]
    public async Task DataThatRacesTheActivationIsDeliveredRatherThanReset()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        var dial = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var handler = CreateHandler(writer, [Mapping(17021, port)], GatedConnector(dial, port));
        handler.Bind(timeout.Token);
        var accepted = listener.AcceptTcpClientAsync(timeout.Token);

        await handler.HandleAsync(Open(81, 17021));
        Assert.True(handler.HasPendingStream(81));
        handler.AfterLiveLookupMissForTests = async streamId =>
        {
            handler.AfterLiveLookupMissForTests = null;
            dial.SetResult();
            await WaitUntilAsync(() => handler.HasTcpStream(streamId), timeout.Token);
        };
        await handler.HandleAsync(Data(81, "abc"));

        using var peer = await accepted;
        await WaitUntilAsync(() => transport.Length > 0, timeout.Token);
        var answer = Assert.Single(await ReadFramesAsync(transport, 1, timeout.Token));
        Assert.NotEqual(NatMessageType.Rst, answer.NatMessageType);
        var received = new byte[3];
        await peer.GetStream().ReadExactlyAsync(received, timeout.Token);
        Assert.Equal("abc", Encoding.ASCII.GetString(received));
        Assert.True(handler.HasTcpStream(81));
    }

    // Packets buffered while the dial was in flight belong in front of anything that arrives after
    // it. They were replayed by the dialling task while the reader already wrote new DATA straight
    // to the socket, so the local application could read the second chunk before the first.
    [Fact]
    public async Task DataBufferedDuringTheDialReachesTheSocketBeforeDataThatArrivesAfter()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        var dial = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var handler = CreateHandler(writer, [Mapping(17022, port)], GatedConnector(dial, port));
        handler.Bind(timeout.Token);
        var accepted = listener.AcceptTcpClientAsync(timeout.Token);

        await handler.HandleAsync(Open(82, 17022));
        await handler.HandleAsync(Data(82, "first-"));
        var held = HoldBufferedDelivery(handler);
        dial.SetResult();
        await held.Reached.Task.WaitAsync(timeout.Token);
        await handler.HandleAsync(Data(82, "second"));
        held.Release.SetResult();

        using var peer = await accepted;
        var received = new byte[12];
        await peer.GetStream().ReadExactlyAsync(received, timeout.Token);
        Assert.Equal("first-second", Encoding.ASCII.GetString(received));
    }

    // The same hand-off for a FIN: it half-closes the socket, so arriving ahead of buffered DATA it
    // turned that DATA into a write after FIN and reset the stream instead of delivering it.
    [Fact]
    public async Task FinArrivingDuringTheHandOffClosesOnlyAfterTheBufferedData()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        var dial = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var handler = CreateHandler(writer, [Mapping(17023, port)], GatedConnector(dial, port));
        handler.Bind(timeout.Token);
        var accepted = listener.AcceptTcpClientAsync(timeout.Token);

        await handler.HandleAsync(Open(83, 17023));
        await handler.HandleAsync(Data(83, "payload"));
        var held = HoldBufferedDelivery(handler);
        dial.SetResult();
        await held.Reached.Task.WaitAsync(timeout.Token);
        await handler.HandleAsync(new NatMessagePacket { NatMessageType = NatMessageType.Fin, StreamId = 83 });
        held.Release.SetResult();

        using var peer = await accepted;
        var received = new byte[7];
        await peer.GetStream().ReadExactlyAsync(received, timeout.Token);
        Assert.Equal("payload", Encoding.ASCII.GetString(received));
        Assert.Equal(0, await peer.GetStream().ReadAsync(new byte[1], timeout.Token));
    }

    // A reset that lands while buffered packets are being handed over ends the stream there: it is
    // not published as live afterwards, and nothing is left pending for it.
    [Fact]
    public async Task ResetDuringTheHandOffReleasesTheStreamWithoutPublishingIt()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        var dial = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var handler = CreateHandler(writer, [Mapping(17024, port)], GatedConnector(dial, port));
        handler.Bind(timeout.Token);
        var accepted = listener.AcceptTcpClientAsync(timeout.Token);

        await handler.HandleAsync(Open(84, 17024));
        await handler.HandleAsync(Data(84, "x"));
        var held = HoldBufferedDelivery(handler);
        dial.SetResult();
        await held.Reached.Task.WaitAsync(timeout.Token);
        await handler.HandleAsync(new NatMessagePacket { NatMessageType = NatMessageType.Rst, StreamId = 84 });
        held.Release.SetResult();

        using var peer = await accepted;
        await WaitUntilAsync(() => !handler.HasTcpStream(84) && !handler.HasPendingStream(84), timeout.Token);
        await Task.Delay(100, timeout.Token);
        Assert.False(handler.HasTcpStream(84));
        Assert.False(handler.HasPendingStream(84));
    }

    private static NatMessagePacket Data(uint streamId, string text) => new()
    {
        NatMessageType = NatMessageType.Data,
        StreamId = streamId,
        Data = Encoding.ASCII.GetBytes(text),
    };

    // A dial that waits for the test to let it complete, then connects to the listener it names.
    private static Func<string, int, CancellationToken, Task<TcpClient>> GatedConnector(
        TaskCompletionSource gate, int listenerPort) =>
        async (address, port, cancellationToken) =>
        {
            _ = address;
            _ = port;
            await gate.Task.WaitAsync(cancellationToken);
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, listenerPort, cancellationToken);
            return client;
        };

    // Pauses the hand-off once it holds the buffered packets, until the test releases it.
    private static (TaskCompletionSource Reached, TaskCompletionSource Release) HoldBufferedDelivery(
        NatClientHandler handler)
    {
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.BeforeBufferedDeliveryForTests = async _ =>
        {
            handler.BeforeBufferedDeliveryForTests = null;
            reached.SetResult();
            await release.Task;
        };
        return (reached, release);
    }

    private static SpecusConfigEntry Mapping(int publicPort, int targetPort) => new()
    {
        Port = publicPort,
        SpecusAddress = IPAddress.Loopback.ToString(),
        SpecusPort = targetPort,
    };

    private static NatMessagePacket Open(uint streamId, int port) => new()
    {
        NatMessageType = NatMessageType.Open,
        StreamId = streamId,
        MetaData = new Dictionary<string, object?>
        {
            ["port"] = port,
            ["channelId"] = $"tcp-{streamId}",
        },
    };

    private static NatClientHandler CreateHandler(
        FrameWriter writer, IReadOnlyList<SpecusConfigEntry> mappings,
        Func<string, int, CancellationToken, Task<TcpClient>>? connector = null)
    {
        var directHttp = new DirectHttpHandler(
            Enumerable.Empty<HttpSpecusConfigEntry>(),
            writer,
            new DirectHttpForwarder(new HttpClient()),
            NullLogger<DirectHttpHandler>.Instance);
        return new NatClientHandler(
            mappings,
            "tcp-test",
            writer,
            directHttp,
            NullLogger<NatClientHandler>.Instance,
            connector);
    }

    private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken cancellationToken)
    {
        while (!condition())
        {
            await Task.Delay(10, cancellationToken);
        }
    }

    private static async Task<List<NatMessagePacket>> ReadFramesAsync(
        MemoryStream transport, int count, CancellationToken cancellationToken)
    {
        transport.Position = 0;
        var reader = PipeReader.Create(transport, new StreamPipeReaderOptions(leaveOpen: true));
        var frames = new List<NatMessagePacket>(count);
        try
        {
            for (var i = 0; i < count; i++)
            {
                frames.Add(Assert.IsType<NatMessagePacket>(
                    await FrameReader.ReadFrameAsync(reader, 32 * 1024 * 1024, cancellationToken)));
            }
        }
        finally
        {
            await reader.CompleteAsync();
        }
        return frames;
    }
}
