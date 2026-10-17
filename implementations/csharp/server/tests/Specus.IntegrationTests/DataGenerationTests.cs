using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Nat;
using Specus.Server.Networking;

namespace Specus.IntegrationTests;

public sealed class DataGenerationTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    [Fact(Timeout = 60_000)]
    public async Task CurrentDataStillServesHttpWhileControlLifecycleLeaseIsHeld()
    {
        await using var fixture = await ControlGenerationTests.Fixture.StartAsync(2);
        var auth = await fixture.AuthenticateAsync();
        await SeedRouteAsync(fixture.Server, auth);
        using var control = await fixture.LoginAsync(auth, ConnectionRole.Control);
        using var data = await fixture.LoginAsync(auth, ConnectionRole.Data);
        using var lease = await fixture.Registry.AcquireLifecycleAsync(auth.ClientId, CancellationToken.None);
        await AssertRealHttpAsync(fixture.Server, auth.ClientName, data);
    }

    [Theory(Timeout = 60_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OriginalOldDataHandlerCannotReattachAfterItsClose(bool register)
    {
        await using var fixture = await ControlGenerationTests.Fixture.StartAsync(2);
        var auth = await fixture.AuthenticateAsync();
        await SeedRouteAsync(fixture.Server, auth);
        using var control = await fixture.LoginAsync(auth, ConnectionRole.Control);
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Data);
        var original = fixture.Registry.FindData(auth.ClientName)!;
        fixture.Dispatcher.HeldClose = original;
        using var fresh = await fixture.LoginAsync(auth, ConnectionRole.Data);
        await fixture.Dispatcher.CloseObserved.Task.WaitAsync(Timeout);
        // The actual original data-close callback ran; now replay a frame admitted before close.
        await fixture.Dispatcher.Inner.OnConnectionClosedAsync(original);
        var nat = fixture.Server.HostServices.GetRequiredService<NatServerHandler>();
        var port = FreePort();
        _ = await Record.ExceptionAsync(() => nat.HandleAsync(original, register
            ? Register(auth.ClientName, port)
            : new NatMessagePacket { NatMessageType = NatMessageType.Keepalive }));

        Assert.False(fixture.Server.HostServices.GetRequiredService<RemotePortServerManager>().HasBinding(port),
            "retired data frame leaked a new public listener");
        await AssertRealHttpAsync(fixture.Server, auth.ClientName, fresh);
    }

    [Fact(Timeout = 60_000)]
    public async Task FrameAdmittedOnOldDataCannotReattachAfterReplacement()
    {
        SpecusConnectionContext? selected = null;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var fixture = await ControlGenerationTests.Fixture.StartAsync(2, configureServices: services =>
        {
            services.RemoveAll<NatServerHandler>();
            services.AddSingleton(provider =>
            {
                var nat = ActivatorUtilities.CreateInstance<NatServerHandler>(provider);
                nat.HandlingForTests = async context =>
                {
                    if (!ReferenceEquals(Volatile.Read(ref selected), context)) return;
                    entered.TrySetResult();
                    await release.Task.WaitAsync(Timeout);
                };
                return nat;
            });
        });
        var auth = await fixture.AuthenticateAsync();
        await SeedRouteAsync(fixture.Server, auth);
        using var control = await fixture.LoginAsync(auth, ConnectionRole.Control);
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Data);
        var original = fixture.Registry.FindData(auth.ClientName)!;
        fixture.Dispatcher.HeldClose = original;
        Volatile.Write(ref selected, original);
        try
        {
            await ControlGenerationTests.SendAsync(old, new NatMessagePacket { NatMessageType = NatMessageType.Keepalive });
            await entered.Task.WaitAsync(Timeout); // Already passed the real dispatcher's auth snapshot.
            using var fresh = await fixture.LoginAsync(auth, ConnectionRole.Data);
            await fixture.Dispatcher.Inner.OnConnectionClosedAsync(original);
            release.TrySetResult();
            await fixture.Dispatcher.CloseObserved.Task.WaitAsync(Timeout); // Old dispatch actually returned.
            await AssertRealHttpAsync(fixture.Server, auth.ClientName, fresh);
        }
        finally { release.TrySetResult(); }
    }

    [Fact(Timeout = 60_000)]
    public async Task ReplacementReleasesOldListenerAndBudgetBeforeAckAndLateFinallyCannotReleaseNewBudget()
    {
        var oldFinally = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFinally = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finallyFinished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        NatClientSession? firstNamespace = null;
        await using var fixture = await ControlGenerationTests.Fixture.StartAsync(2, configureServices: services =>
        {
            services.Configure<NettyServerOptions>(options => options.MaxExternalConnections = 1);
            services.RemoveAll<NatServerHandler>();
            services.AddSingleton(provider =>
            {
                var nat = ActivatorUtilities.CreateInstance<NatServerHandler>(provider);
                nat.SessionCreatedForTests = session =>
                {
                    if (Interlocked.CompareExchange(ref firstNamespace, session, null) is not null) return;
                    session.ExternalReleasedForTests = () => finallyFinished.TrySetResult();
                    session.BeforeExternalReleaseForTests = async () =>
                    {
                        oldFinally.TrySetResult();
                        await releaseFinally.Task.WaitAsync(Timeout);
                    };
                };
                return nat;
            });
        });
        var auth = await fixture.AuthenticateAsync();
        using var control = await fixture.LoginAsync(auth, ConnectionRole.Control);
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Data);
        var original = fixture.Registry.FindData(auth.ClientName)!;
        fixture.Dispatcher.HeldClose = original;
        var ports = fixture.Server.HostServices.GetRequiredService<RemotePortServerManager>();
        var port = FreePort();
        await RegisterAsync(old, auth.ClientName, port);
        using var oldPublic = new TcpClient();
        await oldPublic.ConnectAsync(IPAddress.Loopback, port);
        Assert.Equal(NatMessageType.Open, (await ReadNatAsync(old, NatMessageType.Open)).NatMessageType);
        Assert.Equal(1, ports.ActiveExternalConnections);
        try
        {
            using var fresh = await fixture.LoginAsync(auth, ConnectionRole.Data);
            await oldFinally.Task.WaitAsync(Timeout);
            // The old finally is deliberately still blocked. Its actual listener/socket/admission
            // must already be retired before this new login response became visible.
            Assert.False(ports.HasBinding(port));
            Assert.Equal(0, ports.ActiveExternalConnections);
            await AssertClosedAsync(oldPublic);
            await RegisterAsync(fresh, auth.ClientName, port);
            using var currentPublic = new TcpClient();
            await currentPublic.ConnectAsync(IPAddress.Loopback, port);
            var currentOpen = await ReadNatAsync(fresh, NatMessageType.Open);
            Assert.Equal(1, ports.ActiveExternalConnections);
            releaseFinally.TrySetResult();
            await finallyFinished.Task.WaitAsync(Timeout);
            await fixture.Dispatcher.Inner.OnConnectionClosedAsync(original);
            await RoundTripTcpAsync(currentPublic, fresh, currentOpen.StreamId, "new-generation");
            Assert.True(ports.HasBinding(port));
            Assert.Equal(1, ports.ActiveExternalConnections);
            currentPublic.Dispose();
            fresh.Dispose();
            var deadline = DateTime.UtcNow.Add(Timeout);
            while (ports.ActiveExternalConnections != 0 || ports.HasBinding(port))
            {
                Assert.True(DateTime.UtcNow < deadline, "final data close did not release listener/admission");
                await Task.Delay(20);
            }
        }
        finally { releaseFinally.TrySetResult(); }
    }

    private static async Task AssertClosedAsync(TcpClient tcp)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try { Assert.Equal(0, await tcp.GetStream().ReadAsync(new byte[1], timeout.Token)); }
        catch (IOException) { /* A transport reset is also a closed old public socket. */ }
    }

    private static async Task RegisterAsync(TcpClient tcp, string client, int port)
    {
        await ControlGenerationTests.SendAsync(tcp, Register(client, port));
        var response = await ReadNatAsync(tcp, NatMessageType.RegisterResult);
        Assert.True(JsonSerializer.SerializeToElement(response.MetaData).GetProperty("success").GetBoolean());
    }

    private static async Task<NatMessagePacket> ReadNatAsync(TcpClient tcp, NatMessageType type)
    {
        while (true)
            if (await ControlGenerationTests.ReadAsync(tcp) is NatMessagePacket packet && packet.NatMessageType == type)
                return packet;
    }

    private static async Task RoundTripTcpAsync(TcpClient publicTcp, TcpClient data, uint streamId, string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await publicTcp.GetStream().WriteAsync(bytes, timeout.Token);
        using var observed = new MemoryStream();
        while (observed.Length < bytes.Length)
        {
            var packet = await ReadNatAsync(data, NatMessageType.Data);
            Assert.Equal(streamId, packet.StreamId);
            await observed.WriteAsync(packet.Data!, timeout.Token);
        }
        Assert.Equal(bytes, observed.ToArray());
        await ControlGenerationTests.SendAsync(data,
            new NatMessagePacket { NatMessageType = NatMessageType.Data, StreamId = streamId, Data = bytes });
        var echoed = new byte[bytes.Length];
        await publicTcp.GetStream().ReadExactlyAsync(echoed, timeout.Token);
        Assert.Equal(bytes, echoed);
    }

    [Theory]
    [InlineData("register")]
    [InlineData("http")]
    [InlineData("websocket")]
    public async Task DisposedNamespaceIsTerminalEvenWithALiveContext(string operation)
    {
        var options = Options.Create(new NettyServerOptions());
        await using var ports = new RemotePortServerManager(options, NullLoggerFactory.Instance,
            NullLogger<RemotePortServerManager>.Instance);
        var writer = new CapturingWriter();
        var context = new SpecusConnectionContext("retired-data", "127.0.0.1", writer,
            CancellationToken.None, static () => { }, new ReadGate(CancellationToken.None),
            new WriteBackpressureGate(32 * 1024, 64 * 1024));
        context.OnLoginSuccess("retired-client", 1, 1, ConnectionRole.Data);
        await using var session = new NatClientSession(context, ports, null!, null!, options,
            NullLoggerFactory.Instance, NullLogger<NatClientSession>.Instance);
        await session.DisposeAsync();
        var port = FreePort();
        switch (operation)
        {
            case "register":
                await session.HandleAsync(Register("retired-client", port));
                Assert.False(ports.HasBinding(port), "disposed namespace bound a listener");
                break;
            case "http":
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    session.OpenHttpStreamAsync([], CancellationToken.None));
                break;
            case "websocket":
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    session.OpenWebSocketStreamAsync([], CancellationToken.None));
                break;
        }
        Assert.Empty(writer.Packets);
    }

    internal static async Task SeedRouteAsync(TestServerFixture server, ClientAuthLoginResponse auth)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.UtcNow;
        db.HttpRouteMappings.Add(new HttpRouteMapping
        {
            Id = ClientIdGenerator.NewId(), TenantId = auth.TenantId, ClientId = auth.ClientId,
            ClientName = auth.ClientName, Route = "generation", TargetBaseUrl = "http://127.0.0.1:8080",
            Enabled = true, CreatedAt = now, UpdatedAt = now,
        });
        await db.SaveChangesAsync();
    }

    internal static async Task AssertRealHttpAsync(TestServerFixture server, string clientName, TcpClient data)
    {
        var answering = ServeOneHttpAsync(data);
        try
        {
            using var client = server.CreateClient();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            using var response = await client.GetAsync($"/http/{Uri.EscapeDataString(clientName)}/generation/hello", timeout.Token);
            var body = await response.Content.ReadAsStringAsync(timeout.Token);
            Assert.True(response.StatusCode == HttpStatusCode.OK, $"actual public HTTP {(int)response.StatusCode}: {body}");
            Assert.Equal("fresh-data", body);
            await answering.WaitAsync(Timeout);
        }
        finally
        {
            data.Dispose();
            try { await answering.WaitAsync(Timeout); }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or SocketException) { }
        }
    }

    private static async Task ServeOneHttpAsync(TcpClient data)
    {
        NatMessagePacket open;
        do { open = Assert.IsType<NatMessagePacket>(await ControlGenerationTests.ReadAsync(data)); }
        while (open.NatMessageType != NatMessageType.Open);
        await ControlGenerationTests.SendAsync(data, new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open, StreamId = open.StreamId,
            MetaData = new Dictionary<string, object?>
            {
                ["source"] = "http", ["phase"] = "response", ["statusCode"] = 200,
                ["headers"] = new[] { new[] { "Content-Type", "text/plain" } },
            },
        });
        await ControlGenerationTests.SendAsync(data, new NatMessagePacket
            { NatMessageType = NatMessageType.Data, StreamId = open.StreamId, Data = Encoding.UTF8.GetBytes("fresh-data") });
        await ControlGenerationTests.SendAsync(data, new NatMessagePacket
            { NatMessageType = NatMessageType.Fin, StreamId = open.StreamId });
    }

    internal static NatMessagePacket Register(string client, int port) => new()
    {
        NatMessageType = NatMessageType.Register,
        MetaData = new Dictionary<string, object?>
            { ["clientName"] = client, ["port"] = port, ["specusAddress"] = "127.0.0.1", ["specusPort"] = 8080 },
    };

    internal static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private sealed class CapturingWriter : IFrameWriter
    {
        public List<Packet> Packets { get; } = [];
        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        { Packets.Add(packet); return ValueTask.CompletedTask; }
    }
}
