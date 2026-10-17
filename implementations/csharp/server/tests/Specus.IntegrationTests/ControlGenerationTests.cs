using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.PeerMesh;
using Specus.Server.Services;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

// HTTP HMAC authentication, persisted SQLite sessions and actual TCP framing. A delayed close
// replays the original dispatcher with the original physical context, never a fabricated session.
public sealed class ControlGenerationTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    [Fact(Timeout = 60_000)]
    public async Task SameAuthenticatedSessionCanReplaceAtTheOneInstanceLimit()
    {
        await using var fixture = await Fixture.StartAsync(1);
        var auth = await fixture.AuthenticateAsync();
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Control);
        using var fresh = await fixture.LoginAsync(auth, ConnectionRole.Control);
        await fixture.HeartbeatAsync(fresh);
    }

    [Fact(Timeout = 60_000)]
    public async Task LateOldControlCloseCannotDisconnectTheNewControlOrItsData()
    {
        await using var fixture = await Fixture.StartAsync(2);
        var auth = await fixture.AuthenticateAsync();
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Control);
        var original = fixture.Registry.Find(auth.ClientName)!;
        fixture.Dispatcher.HeldClose = original;
        using var fresh = await fixture.LoginAsync(auth, ConnectionRole.Control);
        await fixture.Dispatcher.CloseObserved.Task.WaitAsync(Timeout);
        using var data = await fixture.LoginAsync(auth, ConnectionRole.Data);
        var current = fixture.Registry.Find(auth.ClientName)!;
        var currentData = fixture.Registry.FindData(auth.ClientName)!;

        await fixture.Dispatcher.Inner.OnConnectionClosedAsync(original).WaitAsync(Timeout);

        Assert.Same(current, fixture.Registry.Find(auth.ClientName));
        Assert.Same(currentData, fixture.Registry.FindData(auth.ClientName));
        Assert.False(currentData.Lifetime.IsCancellationRequested, "old control closed its successor's data");
        await fixture.AssertOnlineAsync(auth, current.ChannelId);
        await fixture.HeartbeatAsync(fresh);
        await fixture.HeartbeatAsync(data);
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var record = await db.ConnectionRecords.AsNoTracking().SingleAsync(r => r.Id == original.ConnectionRecordId);
        Assert.NotNull(record.DisconnectedAt);
    }

    [Fact(Timeout = 60_000)]
    public async Task ZeroCredentialLimitStillDeniesTheSameAuthenticatedSession()
    {
        await using var fixture = await Fixture.StartAsync(2);
        var auth = await fixture.AuthenticateAsync();
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Control);
        await using (var scope = fixture.Server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var credential = await db.ClientCredentials.SingleAsync(c => c.ApiKey == DatabaseInitializer.DemoCredentialApiKey);
            credential.MaxOnlineInstances = 0;
            await db.SaveChangesAsync();
        }
        using var denied = await fixture.LoginAsync(auth, ConnectionRole.Control, expectedSuccess: false);
        await fixture.HeartbeatAsync(old);
    }

    [Fact(Timeout = 60_000)]
    public async Task DifferentAuthenticatedSessionStillConsumesItsOwnQuota()
    {
        await using var fixture = await Fixture.StartAsync(1);
        var auth = await fixture.AuthenticateAsync();
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Control);
        var another = await fixture.AuthenticateAsync();
        Assert.NotEqual(auth.ClientSessionId, another.ClientSessionId);
        Assert.Equal(auth.ClientId, another.ClientId);
        using var denied = await fixture.LoginAsync(another, ConnectionRole.Control, expectedSuccess: false);
        await fixture.HeartbeatAsync(old);
    }

    [Fact(Timeout = 60_000)]
    public async Task NativeDisconnectUsesTheOriginalChannelAsAnAtomicPredicate()
    {
        await using var fixture = await Fixture.StartAsync(2);
        var auth = await fixture.AuthenticateAsync();
        using var control = await fixture.LoginAsync(auth, ConnectionRole.Control);
        var context = fixture.Registry.Find(auth.ClientName)!;
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<ClientAccountService>();
        Assert.False(await service.MarkNettyDisconnectedAsync(auth.ClientSessionId, "not-this-channel", CancellationToken.None));
        await fixture.AssertOnlineAsync(auth, context.ChannelId);
        Assert.True(await service.MarkNettyDisconnectedAsync(auth.ClientSessionId, context.ChannelId, CancellationToken.None));
        Assert.False(await service.MarkNettyDisconnectedAsync(auth.ClientSessionId, context.ChannelId, CancellationToken.None));
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.Equal(ClientAccountService.StatusDisconnected,
            (await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == auth.ClientSessionId)).Status);
    }

    [Fact(Timeout = 60_000)]
    public async Task DifferentSessionCleanupStillRetiresOldStateWhenTheNativeRowIsAlreadyOffline()
    {
        await using var fixture = await Fixture.StartAsync(2);
        var auth = await fixture.AuthenticateAsync();
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Control);
        var original = fixture.Registry.Find(auth.ClientName)!;
        fixture.Dispatcher.HeldClose = original;
        var state = fixture.Server.HostServices.GetRequiredService<PeerMeshServiceState>();
        var oldKey = (auth.TenantId, auth.ClientId, auth.ClientSessionId);
        state.ServiceReportRevisions[oldKey] = 42;
        await using (var scope = fixture.Server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            await db.ClientSessions.Where(s => s.Id == auth.ClientSessionId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.Status, ClientAccountService.StatusDisconnected));
        }
        var another = await fixture.AuthenticateAsync();
        Assert.NotEqual(auth.ClientSessionId, another.ClientSessionId);
        Assert.Equal(auth.ClientId, another.ClientId);
        using var fresh = await fixture.LoginAsync(another, ConnectionRole.Control);
        await fixture.Dispatcher.CloseObserved.Task.WaitAsync(Timeout);
        var newKey = (another.TenantId, another.ClientId, another.ClientSessionId);
        state.ServiceReportRevisions[newKey] = 17;
        await fixture.Dispatcher.Inner.OnConnectionClosedAsync(original);
        Assert.False(state.ServiceReportRevisions.ContainsKey(oldKey));
        Assert.Equal(17, state.ServiceReportRevisions[newKey]);
        await fixture.AssertOnlineAsync(another, fixture.Registry.Find(another.ClientName)!.ChannelId);
        await fixture.HeartbeatAsync(fresh);
    }

    [Fact]
    public async Task LifecycleWaitIsCancellableAndDisposalCannotReleaseAnotherOwner()
    {
        var registry = new SessionRegistry(Microsoft.Extensions.Logging.Abstractions.NullLogger<SessionRegistry>.Instance);
        var first = await registry.AcquireLifecycleAsync(1, CancellationToken.None);
        using var cancel = new CancellationTokenSource();
        var waiting = registry.AcquireLifecycleAsync(1, cancel.Token).AsTask();
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        first.Dispose();
        using var second = await registry.AcquireLifecycleAsync(1, CancellationToken.None);
        first.Dispose();
        using var cancelled = new CancellationTokenSource();
        var stillWaiting = registry.AcquireLifecycleAsync(1, cancelled.Token).AsTask();
        Assert.False(stillWaiting.IsCompleted);
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stillWaiting);
    }

    [Fact(Timeout = 60_000)]
    public async Task NewLoginWaitsUntilTheOldNativeOfflineAndCleanupFinish()
    {
        var barrier = new OfflineBarrier();
        await using var fixture = await Fixture.StartAsync(2, barrier: barrier);
        var auth = await fixture.AuthenticateAsync();
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Control);
        var original = fixture.Registry.Find(auth.ClientName)!;
        fixture.Dispatcher.HeldClose = original;
        original.CloseAsync();
        await fixture.Dispatcher.CloseObserved.Task.WaitAsync(Timeout);
        barrier.Armed = true;
        var closing = fixture.Dispatcher.Inner.OnConnectionClosedAsync(original);
        try
        {
            await barrier.OfflineWritten.Task.WaitAsync(Timeout);
            await using (var scope = fixture.Server.HostServices.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
                Assert.Equal(ClientAccountService.StatusDisconnected,
                    (await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == auth.ClientSessionId)).Status);
            }
            var freshLogin = fixture.LoginAsync(auth, ConnectionRole.Control);
            await Task.Delay(200);
            Assert.False(freshLogin.IsCompleted, "new login crossed native-offline / old-cleanup boundary");
            barrier.Release.TrySetResult();
            using var fresh = await freshLogin.WaitAsync(Timeout);
            await closing.WaitAsync(Timeout);
            await fixture.AssertOnlineAsync(auth, fixture.Registry.Find(auth.ClientName)!.ChannelId);
            await fixture.HeartbeatAsync(fresh);
        }
        finally { barrier.Release.TrySetResult(); await closing.WaitAsync(Timeout); }
    }

    [Fact(Timeout = 60_000)]
    public async Task FailedNewLoginBeforeBindingDoesNotMistakeTheOldBindingForASuccessor()
    {
        var failure = new ConnectionRecordFailure();
        await using var fixture = await Fixture.StartAsync(2, barrier: failure);
        var auth = await fixture.AuthenticateAsync();
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Control);
        var original = fixture.Registry.Find(auth.ClientName)!;
        fixture.Dispatcher.HeldClose = original;
        failure.Armed = true;
        await Assert.ThrowsAnyAsync<IOException>(() => fixture.LoginAsync(auth, ConnectionRole.Control));
        await fixture.Dispatcher.CloseObserved.Task.WaitAsync(Timeout);
        var deadline = DateTime.UtcNow.Add(Timeout);
        while (true)
        {
            await using var scope = fixture.Server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var row = await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == auth.ClientSessionId);
            if (row.Status == ClientAccountService.StatusDisconnected
                && fixture.Registry.Find(auth.ClientName) is null) break;
            Assert.True(DateTime.UtcNow < deadline, "failed login left an online row or the displaced old binding");
            await Task.Delay(20);
        }
        await fixture.Dispatcher.Inner.OnConnectionClosedAsync(original);
    }

    [Fact(Timeout = 60_000)]
    public async Task ReplacementRebasesRawReportsAndRejectsTheOldPhysicalPublisher()
    {
        await using var fixture = await Fixture.StartAsync(3, mesh: true);
        var auth = await fixture.AuthenticateAsync();
        var peerAuth = await fixture.AuthenticateAsync("generation-recipient");
        using var recipient = await fixture.LoginAsync(peerAuth, ConnectionRole.Control);
        using var old = await fixture.LoginAsync(auth, ConnectionRole.Control);
        await fixture.SeedServiceAsync(auth, peerAuth);
        var original = fixture.Registry.Find(auth.ClientName)!;
        fixture.Dispatcher.HeldClose = original;
        await SendAsync(old, Report(long.MaxValue, "old-publisher"));
        var first = await ReadCatalogAsync(recipient);
        Assert.Single(first.Services!);

        using var fresh = await fixture.LoginAsync(auth, ConnectionRole.Control);
        await fixture.Dispatcher.CloseObserved.Task.WaitAsync(Timeout);
        var withdrawal = await ReadCatalogAsync(recipient);
        Assert.Empty(withdrawal.Services!);
        Assert.True(withdrawal.Revision > first.Revision);
        await SendAsync(fresh, Report(1, "new-publisher"));
        var current = await ReadCatalogAsync(recipient);
        Assert.Single(current.Services!);
        Assert.True(current.Revision > withdrawal.Revision);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Dispatcher.Inner.DispatchAsync(original, Report(long.MaxValue, "late-old")));
        await fixture.Dispatcher.Inner.OnConnectionClosedAsync(original);
        var key = (auth.TenantId, auth.ClientId, auth.ClientSessionId);
        var state = fixture.Server.HostServices.GetRequiredService<PeerMeshServiceState>();
        Assert.Equal(1, state.ServiceReportRevisions[key]);
        Assert.Equal("new-publisher", state.ServiceCatalogs[key].InstanceId);
        await fixture.AssertOnlineAsync(auth, fixture.Registry.Find(auth.ClientName)!.ChannelId);
        await SendAsync(recipient, new HeartbeatRequestPacket());
        while (await ReadAsync(recipient) is { } packet && packet is not HeartbeatResponsePacket)
        {
            if (packet is MessageResponsePacket message && message.MessageType == MessageType.PeerControl)
                Assert.NotEqual("service-catalog", JsonSerializer.Deserialize<PeerControlMessage>(message.Message!)!.Type);
        }
    }

    private static MessageRequestPacket Report(long revision, string instance) => new()
    {
        MessageType = MessageType.PeerControl,
        Message = JsonSerializer.Serialize(new
        {
            type = "service-report", enabled = true, revision, instanceId = instance,
            services = new[] { new { serviceId = "svc-generation" } },
        }),
    };

    private static async Task<PeerControlMessage> ReadCatalogAsync(TcpClient tcp)
    {
        while (true)
        {
            if (await ReadAsync(tcp) is MessageResponsePacket { MessageType: MessageType.PeerControl } packet
                && JsonSerializer.Deserialize<PeerControlMessage>(packet.Message!) is { Type: "service-catalog" } catalog)
                return catalog;
        }
    }

    internal sealed class Fixture : IAsyncDisposable
    {
        public required TestServerFixture Server { get; init; }
        public DelayedCloseDispatcher Dispatcher => (DelayedCloseDispatcher)Server.HostServices.GetRequiredService<IControlChannelDispatcher>();
        public SessionRegistry Registry => Server.HostServices.GetRequiredService<SessionRegistry>();

        public static async Task<Fixture> StartAsync(int limit, bool mesh = false, DbCommandInterceptor? barrier = null,
            Action<IServiceCollection>? configureServices = null)
        {
            var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
            {
                ["Specus:ClientAuth:PerMachineUserMaxInstances"] = limit.ToString(),
                ["Specus:ClientAuth:DefaultMaxOnlineInstances"] = limit.ToString(),
                ["Specus:PeerMesh:Enabled"] = mesh.ToString(),
                ["Specus:PeerMesh:StunTurnPort"] = "0",
                ["Specus:PeerMesh:NatProbeAlternatePort"] = "0",
            }, services =>
            {
                services.RemoveAll<IControlChannelDispatcher>();
                services.AddSingleton<IControlChannelDispatcher>(provider => new DelayedCloseDispatcher(
                    ActivatorUtilities.CreateInstance<ControlChannelDispatcher>(provider)));
                if (barrier is not null)
                    services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(barrier));
                configureServices?.Invoke(services);
            });
            return new Fixture { Server = server };
        }

        public async Task<ClientAuthLoginResponse> AuthenticateAsync(string machine = "generation-machine")
        {
            using var client = Server.CreateClient();
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
            var nonce = Guid.NewGuid().ToString("N");
            const string user = "generation-user";
            var signed = string.Join('\n', DatabaseInitializer.DemoCredentialApiKey, timestamp, nonce, machine, user);
            var signature = Convert.ToHexString(HMACSHA256.HashData(
                SHA256.HashData(Encoding.UTF8.GetBytes(DatabaseInitializer.DemoCredentialSecret)),
                Encoding.UTF8.GetBytes(signed))).ToLowerInvariant();
            using var response = await client.PostAsJsonAsync("/api/client/auth/login", new
            {
                apiKey = DatabaseInitializer.DemoCredentialApiKey, timestamp, nonce, signature,
                environment = new { machineFingerprint = machine, osUser = user, hostname = "generation-test",
                    clientPeerServiceCapabilities = new { version = 2, applications = new[] { "http" } } },
            });
            response.EnsureSuccessStatusCode();
            return (await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>())!;
        }

        public async Task SeedServiceAsync(ClientAuthLoginResponse auth, ClientAuthLoginResponse recipient)
        {
            await using var scope = Server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var now = DateTimeOffset.UtcNow;
            foreach (var device in await db.PeerMeshDevices.Where(d =>
                         d.ClientId == auth.ClientId || d.ClientId == recipient.ClientId).ToListAsync())
                device.Enabled = true;
            db.PeerMeshServiceSharings.Add(new PeerMeshServiceSharing
                { TenantId = auth.TenantId, Enabled = true, UpdatedAt = now, UpdatedBy = "test" });
            db.PeerMeshSharedServices.Add(new PeerMeshSharedService
            {
                Id = ClientIdGenerator.NewId(), TenantId = auth.TenantId, ClientId = auth.ClientId,
                ClientName = auth.ClientName, ServiceId = "svc-generation", Name = "generation service",
                Transport = "tcp", Application = "http", TargetHost = "127.0.0.1", TargetPort = 8080,
                PublishedPort = 18080, Path = "/", Enabled = true, Visibility = "OWNER",
                CreatedAt = now, UpdatedAt = now,
            });
            await db.SaveChangesAsync();
        }

        public async Task<TcpClient> LoginAsync(ClientAuthLoginResponse auth, string role, bool expectedSuccess = true)
        {
            var tcp = new TcpClient { NoDelay = true };
            try
            {
                await tcp.ConnectAsync(IPAddress.Loopback, Server.ControlPort);
                await SendAsync(tcp, new LoginRequestPacket
                {
                    ClientName = auth.ClientName, ClientSessionId = auth.ClientSessionId,
                    AccessToken = auth.AccessToken, ConnectionRole = role,
                });
                var response = Assert.IsType<LoginResponsePacket>(await ReadAsync(tcp));
                Assert.True(response.Success == expectedSuccess, response.Reason);
                return tcp;
            }
            catch { tcp.Dispose(); throw; }
        }

        public async Task AssertOnlineAsync(ClientAuthLoginResponse auth, string channelId)
        {
            await using var scope = Server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var row = await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == auth.ClientSessionId);
            Assert.Equal(ClientAccountService.StatusNettyOnline, row.Status);
            Assert.Equal(channelId, row.ChannelId);
            var cached = Server.HostServices.GetRequiredService<ClientAuthSessionStore>().FindById(auth.ClientSessionId)!;
            Assert.Equal(ClientAuthSessionStatus.NettyOnline, cached.Status);
            Assert.Equal(channelId, cached.ChannelId);
        }

        public async Task HeartbeatAsync(TcpClient tcp)
        {
            await SendAsync(tcp, new HeartbeatRequestPacket());
            while (await ReadAsync(tcp) is not HeartbeatResponsePacket) { }
        }

        public ValueTask DisposeAsync() => Server.DisposeAsync();
    }

    private sealed class OfflineBarrier : DbCommandInterceptor
    {
        public volatile bool Armed;
        public TaskCompletionSource OfflineWritten { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
            int result, CancellationToken cancellationToken = default)
        {
            if (Armed && command.CommandText.Contains("UPDATE", StringComparison.OrdinalIgnoreCase)
                && command.CommandText.Contains("specus_client_session", StringComparison.Ordinal)
                && (command.CommandText.Contains("DISCONNECTED", StringComparison.Ordinal)
                    || command.Parameters.Cast<DbParameter>().Any(p => Equals(p.Value, ClientAccountService.StatusDisconnected))))
            {
                Armed = false;
                Assert.Equal(1, result);
                OfflineWritten.TrySetResult();
                await Release.Task.WaitAsync(Timeout, cancellationToken);
            }
            return result;
        }
    }

    private sealed class ConnectionRecordFailure : DbCommandInterceptor
    {
        public volatile bool Armed;
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            if (Armed && command.CommandText.Contains("INSERT INTO \"specus_connection_record\"", StringComparison.Ordinal))
            {
                Armed = false;
                throw new IOException("controlled connection-record failure before binding");
            }
            return ValueTask.FromResult(result);
        }
    }

    internal sealed class DelayedCloseDispatcher(ControlChannelDispatcher inner) : IControlChannelDispatcher
    {
        public ControlChannelDispatcher Inner { get; } = inner;
        public SpecusConnectionContext? HeldClose;
        public TaskCompletionSource CloseObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task OnConnectionOpenedAsync(SpecusConnectionContext context) => Inner.OnConnectionOpenedAsync(context);
        public Task DispatchAsync(SpecusConnectionContext context, Packet packet) => Inner.DispatchAsync(context, packet);
        public Task OnConnectionClosedAsync(SpecusConnectionContext context)
        {
            if (!ReferenceEquals(Volatile.Read(ref HeldClose), context)) return Inner.OnConnectionClosedAsync(context);
            CloseObserved.TrySetResult();
            return Task.CompletedTask;
        }
    }

    internal static Task SendAsync(TcpClient tcp, Packet packet) => tcp.GetStream().WriteAsync(PacketCodec.Encode(packet)).AsTask();

    internal static async Task<Packet> ReadAsync(TcpClient tcp)
    {
        using var timeout = new CancellationTokenSource(Timeout);
        var stream = tcp.GetStream();
        var header = new byte[PacketCodec.HeaderSize];
        await stream.ReadExactlyAsync(header, timeout.Token);
        var (_, length) = PacketCodec.DecodeHeader(header);
        var frame = new byte[PacketCodec.HeaderSize + length];
        header.CopyTo(frame, 0);
        await stream.ReadExactlyAsync(frame.AsMemory(PacketCodec.HeaderSize), timeout.Token);
        return PacketCodec.DecodeExact(frame);
    }
}
