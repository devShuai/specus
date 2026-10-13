using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Networking;
using Specus.Server.PeerMesh;
using Specus.Server.Security;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

public sealed class PeerClientDeletionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HttpDeletionCleansReferencesAndWithdrawsRuntimeState(bool backgroundDispatch)
    {
        await using var fixture = await Fixture.CreateAsync(backgroundDispatch);
        using var response = await fixture.Admin.DeleteAsync("/api/admin/clients/1001");
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(fixture.DeletedClosed);
        if (!backgroundDispatch)
        {
            Assert.Single(fixture.State.ClientDeletions);
            Assert.Empty(fixture.Peer.Messages);
            await fixture.DrainAsync();
        }
        await fixture.Peer.WaitForWithdrawalAsync();
        await fixture.Peer.WaitForRosterAsync();
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.False(await db.ClientAccounts.AnyAsync(row => row.Id == 1001));
        Assert.False(await db.PeerMeshDevices.AnyAsync(row => row.TenantId == "default" && row.ClientId == 1001));
        Assert.False(await db.PeerMeshAcls.AnyAsync(row => row.TenantId == "default"
            && (row.SourceClientId == 1001 || row.TargetClientId == 1001)));
        Assert.False(await db.PeerMeshSharedServices.AnyAsync(row => row.ClientId == 1001 && row.TenantId == "default"));
        Assert.False(await db.PeerMeshEgressPolicies.AnyAsync(row => row.EgressClientId == 1001 && row.TenantId == "default"));
        Assert.True(await db.PeerMeshDevices.AnyAsync(row => row.TenantId == "other" && row.ClientId == 1001));
        Assert.True(await db.PeerMeshAcls.AnyAsync(row => row.TenantId == "other" && row.SourceClientId == 1001));
        foreach (var expected in new[] { (11L, "1004", true), (12L, "", false), (13L, "", true), (14L, "", true), (15L, "1001", true) })
        {
            var service = await db.PeerMeshSharedServices.SingleAsync(row => row.Id == expected.Item1);
            Assert.Equal(expected.Item2, service.AllowedClientIds);
            Assert.Equal(expected.Item3, service.Enabled);
        }
        Assert.Equal("1004", (await db.PeerMeshEgressPolicies.SingleAsync(row => row.Id == 21)).AllowedConsumerClientIds);
        Assert.Equal("", (await db.PeerMeshEgressPolicies.SingleAsync(row => row.Id == 22)).AllowedConsumerClientIds);
        Assert.Equal("1001", (await db.PeerMeshEgressPolicies.SingleAsync(row => row.Id == 23)).AllowedConsumerClientIds);
        var closed = await db.PeerMeshSessions.SingleAsync(row => row.Id == 40);
        Assert.Equal(PeerMeshService.StatusClosed, closed.Status);
        Assert.NotNull(closed.ClosedAt);
        Assert.Equal(7, closed.DirectBytes);
        Assert.Equal(9, closed.RelayBytes);
        Assert.Equal(fixture.HistoricalClose, (await db.PeerMeshSessions.SingleAsync(row => row.Id == 41)).ClosedAt);
        Assert.Equal(PeerMeshService.StatusActive, (await db.PeerMeshSessions.SingleAsync(row => row.Id == 42)).Status);
        Assert.Contains(fixture.Peer.Messages, message => message.Type == "close" && message.SessionId == 40);
        var roster = Assert.Single(fixture.Peer.Messages, message => message.Type == "roster");
        Assert.DoesNotContain(roster.Peers ?? [], peer => peer.ClientId == 1001);
        var config = Assert.Single(fixture.Peer.Messages, message => message.Type == "peer-config").PeerMesh;
        Assert.NotNull(config);
        Assert.DoesNotContain(config!.LocalServices, service => service.ServiceId == "service-12" && service.Enabled);
        Assert.Contains(config.LocalServices, service => service.ServiceId == "service-13" && service.Enabled);
        Assert.Empty(fixture.Foreign.Messages);
        Assert.True(fixture.State.ServiceCatalogs.ContainsKey(("other", 1001, 802)));
        Assert.False(fixture.State.ServiceCatalogs.ContainsKey(("default", 1001, 801)));
    }

    [Fact]
    public async Task FailedAccountDeleteRollsBackReferencesAndPreservesOnlineClient()
    {
        await using var fixture = await Fixture.CreateAsync(false);
        await using (var scope = fixture.Server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            await db.Database.ExecuteSqlRawAsync("""
                CREATE TRIGGER reject_deleted_client BEFORE DELETE ON specus_client_account
                WHEN OLD.id = 1001 BEGIN SELECT RAISE(ABORT, 'injected account delete failure'); END;
                """);
            var mutation = scope.ServiceProvider.GetRequiredService<ManagementMutationService>();
            await Assert.ThrowsAsync<DbUpdateException>(() => mutation.DeleteClientAsync(
                new ManagementContext("default", "admin", ManagementRole.Admin, true), 1001, CancellationToken.None));
        }
        Assert.False(fixture.DeletedClosed);
        Assert.Empty(fixture.State.ClientDeletions);
        await fixture.DrainAsync();
        Assert.Empty(fixture.Peer.Messages);
        Assert.True(fixture.State.ServiceCatalogs.ContainsKey(("default", 1001, 801)));
        await using var verify = fixture.Server.HostServices.CreateAsyncScope();
        var persisted = verify.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.True(await persisted.ClientAccounts.AnyAsync(row => row.Id == 1001));
        Assert.True(await persisted.PeerMeshDevices.AnyAsync(row => row.TenantId == "default" && row.ClientId == 1001));
        Assert.Equal(2, await persisted.PeerMeshAcls.CountAsync(row => row.TenantId == "default"));
        Assert.Equal(5, await persisted.PeerMeshSharedServices.CountAsync(row => row.TenantId == "default"));
        var service = await persisted.PeerMeshSharedServices.SingleAsync(row => row.Id == 12);
        Assert.True(service.Enabled);
        Assert.Equal("1001", service.AllowedClientIds);
        var session = await persisted.PeerMeshSessions.SingleAsync(row => row.Id == 40);
        Assert.Equal(PeerMeshService.StatusActive, session.Status);
        Assert.Null(session.ClosedAt);
    }

    [Fact]
    public async Task FailedWithdrawalRetriesAfterCacheRemovalWithoutBlockingHealthyPeer()
    {
        await using var fixture = await Fixture.CreateAsync(false);
        fixture.Peer.FailWithdrawalOnce = true;
        using var response = await fixture.Admin.DeleteAsync("/api/admin/clients/1001");
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        await fixture.DrainAsync();
        var pending = Assert.Single(fixture.State.ClientDeletions);
        var revision = Assert.Single(pending.Withdrawals).Value;
        Assert.False(fixture.State.ServiceCatalogs.ContainsKey(("default", 1001, 801)));
        Assert.Contains(fixture.Healthy.Messages, message => message.Type == "service-catalog" && message.PublisherClientId == 1001);
        Assert.DoesNotContain(fixture.Peer.Messages, message => message.Type == "service-catalog" && message.PublisherClientId == 1001);
        await fixture.DrainAsync();
        Assert.Empty(fixture.State.ClientDeletions);
        var withdrawn = Assert.Single(fixture.Peer.Messages, message => message.Type == "service-catalog" && message.PublisherClientId == 1001);
        Assert.Equal(revision, withdrawn.Revision);
        Assert.Empty(withdrawn.Services ?? []);
        Assert.False(fixture.State.ServiceCatalogRevisions.ContainsKey(("default", 1001, 801)));
        Assert.False(fixture.State.ServiceReportRevisions.ContainsKey(("default", 1001, 801)));
        Assert.False(fixture.State.ServiceReportWindows.ContainsKey(801));
    }

    private sealed class Fixture(TestServerFixture server) : IAsyncDisposable
    {
        public TestServerFixture Server { get; } = server;
        public PeerMeshServiceState State => Server.HostServices.GetRequiredService<PeerMeshServiceState>();
        public HttpClient Admin { get; private set; } = null!;
        public Writer Peer { get; } = new();
        public Writer Healthy { get; } = new();
        public Writer Foreign { get; } = new();
        private int _closed;
        public bool DeletedClosed => Volatile.Read(ref _closed) != 0;
        public DateTimeOffset HistoricalClose { get; } = DateTimeOffset.UtcNow.AddHours(-1);

        public static async Task<Fixture> CreateAsync(bool backgroundDispatch)
        {
            var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
            {
                ["Specus:PeerMesh:Enabled"] = "true",
            }, services =>
            {
                if (!backgroundDispatch)
                {
                    var dispatcher = services.Single(row => row.ServiceType == typeof(IHostedService)
                        && row.ImplementationType == typeof(PeerClientDeletionDispatchService));
                    services.Remove(dispatcher);
                }
            });
            var fixture = new Fixture(server);
            fixture.Admin = server.CreateClient();
            var token = server.HostServices.GetRequiredService<LocalTokenService>().IssueToken("admin", "default", ManagementRole.Admin);
            fixture.Admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            await fixture.SeedAsync();
            return fixture;
        }

        private async Task SeedAsync()
        {
            await using var scope = Server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var now = DateTimeOffset.UtcNow;
            db.PeerMeshServiceSharings.Add(new PeerMeshServiceSharing
            {
                TenantId = "default", Enabled = true, UpdatedAt = now,
            });
            foreach (var id in new[] { 1001L, 1002L, 1003L, 1004L })
            {
                var tenant = id == 1003 ? "other" : "default";
                db.ClientSessions.Add(new ClientSession
                {
                    Id = id + 50000, TenantId = tenant, ClientId = id, ClientName = $"delete-test-{id}",
                    TokenHash = $"delete-session-{id}", Status = "NETTY_ONLINE",
                    MachineFingerprint = "test", OsUser = "test", PeerServiceDiscoveryVersion = 2,
                    HttpLoginAt = now, NettyConnectedAt = now, ExpiresAt = now.AddHours(1),
                });
                db.ClientAccounts.Add(new ClientAccount { Id = id, TenantId = tenant, OwnerUsername = "admin", ClientName = $"delete-test-{id}", PasswordHash = "hash", CreatedAt = now, UpdatedAt = now });
                db.PeerMeshDevices.Add(new PeerMeshDevice { Id = id + 10000, TenantId = tenant, OwnerUsername = "admin", ClientId = id, ClientName = $"delete-test-{id}", VirtualIp = $"100.96.0.{id - 1000}", Cidr = "100.96.0.0/11", Enabled = true, CreatedAt = now, UpdatedAt = now });
            }
            db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 20000, TenantId = "other", OwnerUsername = "admin", ClientId = 1001, ClientName = "legacy-foreign", VirtualIp = "100.96.0.10", Cidr = "100.96.0.0/11", Enabled = true, CreatedAt = now, UpdatedAt = now });
            foreach (var (id, source, target, tenant) in new[] { (30L, 1001L, 1002L, "default"), (31L, 1002L, 1001L, "default"), (32L, 1001L, 1002L, "other") })
                db.PeerMeshAcls.Add(new PeerMeshAcl { Id = id, TenantId = tenant, SourceClientId = source, TargetClientId = target, SourceClientName = "source", TargetClientName = "target", Direction = "BOTH", CreatedAt = now, UpdatedAt = now });
            foreach (var (id, allowed, visibility, tenant) in new[] { (10L, "", "ACL", "default"), (11L, "1001,1004", "ACL", "default"), (12L, "1001", "ACL", "default"), (13L, "", "ACL", "default"), (14L, "1001", "OWNER", "default"), (15L, "1001", "ACL", "other") })
                db.PeerMeshSharedServices.Add(new PeerMeshSharedService { Id = id, TenantId = tenant, ClientId = id == 10 ? 1001 : 1002, ClientName = id == 10 ? "delete-test-1001" : "delete-test-1002", ServiceId = $"service-{id}", Name = "test", TargetPort = 80, PublishedPort = (int)(18000 + id), Visibility = visibility, Enabled = true, AllowedClientIds = allowed, CreatedAt = now, UpdatedAt = now });
            foreach (var (id, allowed, tenant) in new[] { (20L, "", "default"), (21L, "1001,1004", "default"), (22L, "1001", "default"), (23L, "1001", "other") })
                db.PeerMeshEgressPolicies.Add(new PeerMeshEgressPolicy { Id = id, TenantId = tenant, EgressClientId = id == 20 ? 1001 : 1002 + (id - 21), EgressClientName = "egress", AllowedConsumerClientIds = allowed, Scope = "ACL", Enabled = true, CreatedAt = now, UpdatedAt = now });
            for (var id = 40L; id <= 42; id++)
                db.PeerMeshSessions.Add(new PeerMeshSession { Id = id, TenantId = id == 42 ? "other" : "default", SourceClientId = 1001, SourceClientName = "delete-test-1001", TargetClientId = 1002, TargetClientName = "delete-test-1002", PathType = "RELAY", Status = id == 41 ? PeerMeshService.StatusClosed : PeerMeshService.StatusActive, ClosedAt = id == 41 ? HistoricalClose : null, StartedAt = now, UpdatedAt = now, ExpiresAt = now.AddHours(1), DirectBytes = 7, RelayBytes = 9 });
            await db.SaveChangesAsync();
            Bind(1001, "default", new Writer(), () => Interlocked.Exchange(ref _closed, 1));
            Bind(1002, "default", Peer, () => { });
            Bind(1004, "default", Healthy, () => { });
            Bind(1003, "other", Foreign, () => { });
            foreach (var key in new[] { ("default", 1001L, 801L), ("other", 1001L, 802L) })
            {
                State.ServiceCatalogs[key] = new PeerMeshServiceCatalogSnapshot(3, "test", now, now.AddMinutes(1), [new AdvertisedService { ServiceId = "service-10" }], "delete-test-1001", [], []);
                State.ServiceCatalogRevisions[key] = 3;
                State.ServiceReportRevisions[key] = 3;
                State.ServiceReportWindows[key.Item3] = new ConcurrentQueue<long>([now.ToUnixTimeMilliseconds()]);
            }
        }

        private void Bind(long id, string tenant, IFrameWriter writer, Action close)
        {
            var context = new SpecusConnectionContext($"delete-{id}", "127.0.0.1:12345", writer, CancellationToken.None, close,
                new ReadGate(CancellationToken.None), new WriteBackpressureGate(32768, 65536));
            context.OnLoginSuccess($"delete-test-{id}", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), tenantId: tenant);
            Server.HostServices.GetRequiredService<SessionRegistry>().Replace(context.ClientName!, context);
        }
        public async Task DrainAsync()
        {
            await using var scope = Server.HostServices.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<PeerMeshService>().DrainClientDeletionsAsync(CancellationToken.None);
        }
        public async ValueTask DisposeAsync() { Admin.Dispose(); await Server.DisposeAsync(); }
    }

    private sealed class Writer : IFrameWriter
    {
        private readonly ConcurrentQueue<PeerControlMessage> _messages = new();
        private readonly Channel<PeerControlMessage> _channel = Channel.CreateUnbounded<PeerControlMessage>();
        public bool FailWithdrawalOnce { get; set; }
        public IReadOnlyList<PeerControlMessage> Messages => _messages.ToArray();
        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            var response = Assert.IsType<MessageResponsePacket>(packet);
            var message = JsonSerializer.Deserialize<PeerControlMessage>(response.Message!)!;
            if (FailWithdrawalOnce && message.Type == "service-catalog" && message.PublisherClientId == 1001)
            { FailWithdrawalOnce = false; throw new IOException("injected catalog write failure"); }
            _messages.Enqueue(message); _channel.Writer.TryWrite(message); return ValueTask.CompletedTask;
        }
        public async Task WaitForWithdrawalAsync()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (true)
            {
                var message = await _channel.Reader.ReadAsync(timeout.Token);
                if (message.Type == "service-catalog" && message.PublisherClientId == 1001)
                { Assert.Empty(message.Services ?? []); Assert.True(message.Revision > 3); return; }
            }
        }
        public async Task WaitForRosterAsync()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while ((await _channel.Reader.ReadAsync(timeout.Token)).Type != "roster") { }
        }
    }
}
