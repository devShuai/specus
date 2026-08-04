using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Nat;
using Specus.Server.Networking;

namespace Specus.IntegrationTests;

public sealed class ExternalConnectionTests
{
    [Fact]
    public async Task PublicEofKeepsClientToPublicDirectionUntilClientFin()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var (server, peer) = await ConnectedPairAsync(timeout.Token);
        using var peerOwner = peer;
        using var services = new TestServices();
        var writer = new CapturingFrameWriter();
        var context = CreateContext(writer, timeout.Token);
        await using var external = new ExternalConnection(
            server, 27, 7027, "server-test", context,
            services.Traffic, services.Inspection, new NettyServerOptions(), NullLogger.Instance);

        var run = external.RunAsync(timeout.Token);
        Assert.Equal(NatMessageType.Open, (await writer.WaitAsync(timeout.Token)).NatMessageType);

        var peerStream = peer.GetStream();
        peer.Client.Shutdown(SocketShutdown.Send);
        Assert.Equal(NatMessageType.Fin, (await writer.WaitAsync(timeout.Token)).NatMessageType);
        Assert.True(external.PublicFinished);
        Assert.False(external.ClientFinished);
        Assert.False(external.IsClosed);
        Assert.False(run.IsCompleted);

        var response = "response-after-public-fin"u8.ToArray();
        Assert.Equal(ExternalWriteResult.Written,
            await external.WriteFromClientAsync(response, timeout.Token));
        var received = new byte[response.Length];
        await peerStream.ReadExactlyAsync(received, timeout.Token);
        Assert.Equal(response, received);

        Assert.Equal(ExternalFinResult.Completed, external.FinishClientDirection());
        await run;
        Assert.True(external.ClientFinished);
        Assert.True(external.IsClosed);
    }

    [Fact]
    public async Task ClientFinKeepsPublicToClientDirectionUntilPublicEof()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var (server, peer) = await ConnectedPairAsync(timeout.Token);
        using var peerOwner = peer;
        using var services = new TestServices();
        var writer = new CapturingFrameWriter();
        var context = CreateContext(writer, timeout.Token);
        await using var external = new ExternalConnection(
            server, 28, 7028, "server-test", context,
            services.Traffic, services.Inspection, new NettyServerOptions(), NullLogger.Instance);

        var run = external.RunAsync(timeout.Token);
        Assert.Equal(NatMessageType.Open, (await writer.WaitAsync(timeout.Token)).NatMessageType);

        Assert.Equal(ExternalFinResult.Accepted, external.FinishClientDirection());
        Assert.Equal(ExternalFinResult.Invalid, external.FinishClientDirection());
        Assert.Equal(ExternalWriteResult.DataAfterFin,
            await external.WriteFromClientAsync([1], timeout.Token));
        var eofProbe = new byte[1];
        Assert.Equal(0, await peer.GetStream().ReadAsync(eofProbe, timeout.Token));

        var request = "request-after-client-fin"u8.ToArray();
        await peer.GetStream().WriteAsync(request, timeout.Token);
        var data = await writer.WaitAsync(timeout.Token);
        Assert.Equal(NatMessageType.Data, data.NatMessageType);
        Assert.Equal(request, data.Data);
        peer.Client.Shutdown(SocketShutdown.Send);

        Assert.Equal(NatMessageType.Fin, (await writer.WaitAsync(timeout.Token)).NatMessageType);
        await run;
        Assert.True(external.PublicFinished);
        Assert.True(external.IsClosed);
    }

    [Fact]
    public async Task ClientResetImmediatelyClosesBothDirections()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var (server, peer) = await ConnectedPairAsync(timeout.Token);
        using var peerOwner = peer;
        using var services = new TestServices();
        var writer = new CapturingFrameWriter();
        var context = CreateContext(writer, timeout.Token);
        await using var external = new ExternalConnection(
            server, 29, 7029, "server-test", context,
            services.Traffic, services.Inspection, new NettyServerOptions(), NullLogger.Instance);

        var run = external.RunAsync(timeout.Token);
        Assert.Equal(NatMessageType.Open, (await writer.WaitAsync(timeout.Token)).NatMessageType);

        external.ResetFromClient();
        external.ResetFromClient();

        await run;
        Assert.True(external.IsClosed);
        Assert.Equal(ExternalWriteResult.Reset,
            await external.WriteFromClientAsync([1], timeout.Token));
    }

    [Theory]
    [InlineData(NatMessageType.Data)]
    [InlineData(NatMessageType.Fin)]
    public async Task FrameAfterClientFinResetsOnlyTheTcpStream(NatMessageType offendingType)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var services = new TestServices();
        var options = Options.Create(new NettyServerOptions());
        await using var remotePorts = new RemotePortServerManager(
            options, NullLoggerFactory.Instance, NullLogger<RemotePortServerManager>.Instance);
        var writer = new CapturingFrameWriter();
        var closeCount = 0;
        var context = new SpecusConnectionContext(
            "tcp-state-test",
            "127.0.0.1",
            writer,
            timeout.Token,
            () => Interlocked.Increment(ref closeCount),
            new ReadGate(timeout.Token),
            new WriteBackpressureGate(32 * 1024, 64 * 1024));
        context.OnLoginSuccess("server-test", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            1, ConnectionRole.Data);
        await using var session = new NatClientSession(
            context, remotePorts, services.Traffic, services.Inspection, options,
            NullLoggerFactory.Instance, NullLogger<NatClientSession>.Instance);
        var port = FreeTcpPort();

        await session.HandleAsync(Register(port));
        var register = await writer.WaitAsync(timeout.Token);
        Assert.Equal(NatMessageType.RegisterResult, register.NatMessageType);
        Assert.True(Assert.IsType<bool>(register.MetaData!["success"]));

        using var peer = new TcpClient();
        await peer.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        var open = await writer.WaitAsync(timeout.Token);
        Assert.Equal(NatMessageType.Open, open.NatMessageType);

        await session.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = open.StreamId,
        });
        Assert.Equal(0, await peer.GetStream().ReadAsync(new byte[1], timeout.Token));

        await session.HandleAsync(new NatMessagePacket
        {
            NatMessageType = offendingType,
            StreamId = open.StreamId,
            Data = offendingType == NatMessageType.Data ? [1] : null,
        });

        var reset = await writer.WaitAsync(timeout.Token);
        Assert.Equal(NatMessageType.Rst, reset.NatMessageType);
        Assert.Equal(open.StreamId, reset.StreamId);
        Assert.Equal(0, Volatile.Read(ref closeCount));
    }

    [Fact]
    public async Task UnknownTcpDataSendsResetAndKeepsControlConnection()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var services = new TestServices();
        var options = Options.Create(new NettyServerOptions());
        await using var remotePorts = new RemotePortServerManager(
            options, NullLoggerFactory.Instance, NullLogger<RemotePortServerManager>.Instance);
        var writer = new CapturingFrameWriter();
        var closeCount = 0;
        var context = new SpecusConnectionContext(
            "unknown-stream-test",
            "127.0.0.1",
            writer,
            timeout.Token,
            () => Interlocked.Increment(ref closeCount),
            new ReadGate(timeout.Token),
            new WriteBackpressureGate(32 * 1024, 64 * 1024));
        context.OnLoginSuccess("server-test", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            1, ConnectionRole.Data);
        await using var session = new NatClientSession(
            context, remotePorts, services.Traffic, services.Inspection, options,
            NullLoggerFactory.Instance, NullLogger<NatClientSession>.Instance);
        var port = FreeTcpPort();

        await session.HandleAsync(Register(port));
        Assert.Equal(NatMessageType.RegisterResult,
            (await writer.WaitAsync(timeout.Token)).NatMessageType);

        await session.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = 0xdead,
            Data = [1],
        });

        var reset = await writer.WaitAsync(timeout.Token);
        Assert.Equal(NatMessageType.Rst, reset.NatMessageType);
        Assert.Equal(0xdeadU, reset.StreamId);
        Assert.Equal(0, Volatile.Read(ref closeCount));
    }

    [Fact]
    public async Task LateResetForRecentlyClosedTcpStreamIsTolerated()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var services = new TestServices();
        var options = Options.Create(new NettyServerOptions());
        await using var remotePorts = new RemotePortServerManager(
            options, NullLoggerFactory.Instance, NullLogger<RemotePortServerManager>.Instance);
        var writer = new CapturingFrameWriter();
        var closeCount = 0;
        var context = new SpecusConnectionContext(
            "late-rst-test", "127.0.0.1", writer, timeout.Token,
            () => Interlocked.Increment(ref closeCount),
            new ReadGate(timeout.Token),
            new WriteBackpressureGate(32 * 1024, 64 * 1024));
        context.OnLoginSuccess("server-test", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            1, ConnectionRole.Data);
        await using var session = new NatClientSession(
            context, remotePorts, services.Traffic, services.Inspection, options,
            NullLoggerFactory.Instance, NullLogger<NatClientSession>.Instance);
        var port = FreeTcpPort();

        await session.HandleAsync(Register(port));
        await writer.WaitAsync(timeout.Token);
        using var peer = new TcpClient();
        await peer.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        var open = await writer.WaitAsync(timeout.Token);

        peer.Client.Shutdown(SocketShutdown.Send);
        Assert.Equal(NatMessageType.Fin, (await writer.WaitAsync(timeout.Token)).NatMessageType);
        await session.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = open.StreamId,
        });
        await WaitUntilAsync(() => session.IsClosedStream(open.StreamId), timeout.Token);
        Assert.False(session.HasExternalStream(open.StreamId));

        await session.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Rst,
            StreamId = open.StreamId,
        });
        Assert.Equal(0, Volatile.Read(ref closeCount));
    }

    [Fact]
    public async Task HttpDataEndStreamQueuesDataBeforeResponseEnd()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var services = new TestServices();
        var options = Options.Create(new NettyServerOptions());
        await using var remotePorts = new RemotePortServerManager(
            options, NullLoggerFactory.Instance, NullLogger<RemotePortServerManager>.Instance);
        var writer = new CapturingFrameWriter();
        var context = new SpecusConnectionContext(
            "http-end-stream-test",
            "127.0.0.1",
            writer,
            timeout.Token,
            static () => { },
            new ReadGate(timeout.Token),
            new WriteBackpressureGate(32 * 1024, 64 * 1024));
        context.OnLoginSuccess("server-test", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            1, ConnectionRole.Data);
        await using var session = new NatClientSession(
            context, remotePorts, services.Traffic, services.Inspection, options,
            NullLoggerFactory.Instance, NullLogger<NatClientSession>.Instance);
        var stream = await session.OpenHttpStreamAsync(
            new Dictionary<string, object?>
            {
                ["source"] = "http",
                ["phase"] = "request",
            },
            timeout.Token);
        var open = await writer.WaitAsync(timeout.Token);

        await session.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open,
            StreamId = open.StreamId,
            MetaData = new Dictionary<string, object?>
            {
                ["source"] = "http",
                ["phase"] = "response",
                ["statusCode"] = 200,
            },
        });
        var payload = "final-response-chunk"u8.ToArray();
        await session.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = open.StreamId,
            Data = payload,
            Flags = NatMessagePacket.FlagEndStream,
        });

        Assert.Equal(200, Convert.ToInt32(
            (await stream.WaitResponseHeadAsync(timeout.Token))["statusCode"]));
        var data = await stream.ReadResponseAsync(timeout.Token);
        Assert.False(data.End);
        Assert.Equal(payload, data.Data);
        var end = await stream.ReadResponseAsync(timeout.Token);
        Assert.True(end.End);
        Assert.Null(end.Data);
    }

    private static SpecusConnectionContext CreateContext(
        IFrameWriter writer, CancellationToken lifetime) => new(
        "external-test",
        "127.0.0.1",
        writer,
        lifetime,
        static () => { },
        new ReadGate(lifetime),
        new WriteBackpressureGate(32 * 1024, 64 * 1024));

    private static async Task<(Socket Server, TcpClient Peer)> ConnectedPairAsync(
        CancellationToken cancellationToken)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        var peer = new TcpClient { NoDelay = true };
        var accepted = listener.AcceptSocketAsync(cancellationToken);
        await peer.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken);
        var server = await accepted;
        server.NoDelay = true;
        return (server, peer);
    }

    private static NatMessagePacket Register(int port) => new()
    {
        NatMessageType = NatMessageType.Register,
        MetaData = new Dictionary<string, object?>
        {
            ["port"] = port,
            ["specusPort"] = 8080,
            ["specusAddress"] = IPAddress.Loopback.ToString(),
            ["clientName"] = "server-test",
        },
    };

    private static int FreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken cancellationToken)
    {
        while (!condition())
        {
            await Task.Delay(10, cancellationToken);
        }
    }

    private sealed class CapturingFrameWriter : IFrameWriter
    {
        private readonly Channel<NatMessagePacket> _frames = Channel.CreateUnbounded<NatMessagePacket>();

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            var nat = Assert.IsType<NatMessagePacket>(packet);
            return _frames.Writer.WriteAsync(nat, cancellationToken);
        }

        public ValueTask<NatMessagePacket> WaitAsync(CancellationToken cancellationToken) =>
            _frames.Reader.ReadAsync(cancellationToken);
    }

    private sealed class TestServices : IDisposable
    {
        private readonly ServiceProvider _services;
        private readonly HttpClient _httpClient = new();

        public TestServices()
        {
            _services = new ServiceCollection().BuildServiceProvider();
            var trafficOptions = Options.Create(new TrafficOptions { CaptureDetailEnabled = false });
            Traffic = new TrafficUsageService(
                _services, trafficOptions, NullLogger<TrafficUsageService>.Instance);
            var elasticsearch = new ElasticsearchTrafficDetailClient(
                Options.Create(new ElasticsearchOptions()), new StaticHttpClientFactory(_httpClient));
            Inspection = new TrafficInspectionService(
                _services, trafficOptions, elasticsearch, NullLogger<TrafficInspectionService>.Instance);
        }

        public TrafficUsageService Traffic { get; }
        public TrafficInspectionService Inspection { get; }

        public void Dispose()
        {
            Inspection.Dispose();
            Traffic.Dispose();
            _httpClient.Dispose();
            _services.Dispose();
        }
    }

    private sealed class StaticHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }
}
