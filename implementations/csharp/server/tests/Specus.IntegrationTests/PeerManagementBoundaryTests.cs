using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Management;
using Specus.Server.Networking;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

public sealed class PeerManagementBoundaryTests
{
    [Fact]
    public async Task NewDeviceOwnerCannotTakeOverAnExistingThirdPartyAclThroughUpsert()
    {
        await using var server = await StartAsync();
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var services = scope.ServiceProvider;
            await PeerManagementOwnershipTests.SeedAsync(services.GetRequiredService<SpecusDbContext>());
            var admin = await OwnerTransferWriterProof.ActorAsync(server, services);
            var preview = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(admin.Context, "501", CancellationToken.None);
            Assert.True((await services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(admin, PathScope.CredentialGroup, "501",
                OwnerTransferWriterProof.Body(PathScope.CredentialGroup, "bob", preview.Revision!), CancellationToken.None)).Response.Changed);
        }
        await using var fresh = server.HostServices.CreateAsyncScope();
        var bob = await ManagementResourceOwnershipTests.ContextAsync(server, fresh.ServiceProvider, "bob", "bob-password");
        await Assert.ThrowsAsync<ArgumentException>(() => fresh.ServiceProvider.GetRequiredService<PeerMeshService>().CreateAclAsync(bob,
            new PeerMeshAclMutation(1001, 1002, false, "BOTH"), CancellationToken.None));
        var db = fresh.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var acl = await db.PeerMeshAcls.AsNoTracking().SingleAsync();
        Assert.Equal("alice", acl.OwnerUsername); Assert.True(acl.Allowed);
        Assert.Equal("bob", (await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1001)).OwnerUsername);
    }

    [Theory]
    [InlineData("device")]
    [InlineData("acl-upsert")]
    [InlineData("acl-delete")]
    public async Task ActualCommitFailureRollsBackPeerConfigurationWithoutRuntimePublication(string operation)
    {
        var fault = new CommitFault();
        await using var server = await StartAsync(fault);
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        await PeerManagementOwnershipTests.SeedAsync(db);
        var alice = await ManagementResourceOwnershipTests.ContextAsync(server, services, "alice", "alice-password");
        using var lifetime = new CancellationTokenSource();
        var writer = new RecordingWriter(); var bound = Bind(server, writer, lifetime.Token);
        fault.Armed = true;
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => ChangeAsync(services.GetRequiredService<PeerMeshService>(), alice, operation));
            Assert.True(fault.Triggered); Assert.Equal(0, writer.Writes);
            Assert.True((await db.PeerMeshDevices.AsNoTracking().SingleAsync()).Enabled);
            Assert.True((await db.PeerMeshAcls.AsNoTracking().SingleAsync()).Allowed);
        }
        finally { server.HostServices.GetRequiredService<SessionRegistry>().Unbind("laptop", bound); lifetime.Cancel(); }
    }

    [Theory]
    [InlineData("device")]
    [InlineData("acl-upsert")]
    [InlineData("acl-delete")]
    public async Task CommittedPeerConfigurationIsVisibleBeforeAnyRuntimePublication(string operation)
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        await PeerManagementOwnershipTests.SeedAsync(db);
        var alice = await ManagementResourceOwnershipTests.ContextAsync(server, services, "alice", "alice-password");
        using var lifetime = new CancellationTokenSource();
        var writer = new RecordingWriter(async () =>
        {
            await using var observer = server.HostServices.CreateAsyncScope();
            var current = observer.ServiceProvider.GetRequiredService<SpecusDbContext>();
            if (operation == "device") Assert.False((await current.PeerMeshDevices.AsNoTracking().SingleAsync()).Enabled);
            else if (operation == "acl-upsert") Assert.False((await current.PeerMeshAcls.AsNoTracking().SingleAsync()).Allowed);
            else Assert.Empty(await current.PeerMeshAcls.AsNoTracking().ToListAsync());
        });
        var bound = Bind(server, writer, lifetime.Token);
        try
        {
            await ChangeAsync(services.GetRequiredService<PeerMeshService>(), alice, operation);
            Assert.True(writer.Writes > 0);
            Assert.Null(db.Database.CurrentTransaction);
        }
        finally { server.HostServices.GetRequiredService<SessionRegistry>().Unbind("laptop", bound); lifetime.Cancel(); }
    }

    private static Task<TestServerFixture> StartAsync(CommitFault? fault = null) => TestServerFixture.StartAsync(
        new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true" },
        fault is null ? null : services => services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(fault)));

    private static SpecusConnectionContext Bind(TestServerFixture server, IFrameWriter writer, CancellationToken lifetime)
    {
        var context = new SpecusConnectionContext("retained-control", "127.0.0.1:12345", writer, lifetime, () => { }, new ReadGate(lifetime), new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        context.OnLoginSuccess("laptop", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), clientSessionId: 901, clientId: 1001);
        server.HostServices.GetRequiredService<SessionRegistry>().Replace("laptop", context);
        return context;
    }

    private static async Task ChangeAsync(PeerMeshService peer, ManagementContext actor, string operation)
    {
        switch (operation)
        {
            case "device": await peer.UpdateDeviceAsync(actor, 1001, new PeerMeshDeviceMutation(false), CancellationToken.None); break;
            case "acl-upsert": await peer.CreateAclAsync(actor, new PeerMeshAclMutation(1001, 1002, false, "BOTH"), CancellationToken.None); break;
            case "acl-delete": await peer.DeleteAclAsync(actor, 4801, CancellationToken.None); break;
            default: throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }

    private sealed class RecordingWriter(Func<Task>? observe = null) : IFrameWriter
    {
        internal int Writes { get; private set; }
        public async ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        { Writes++; if (observe is not null) await observe(); }
    }

    private sealed class CommitFault : DbTransactionInterceptor
    {
        internal bool Armed { get; set; }
        internal bool Triggered { get; private set; }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData eventData,
            InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (Armed) { Triggered = true; throw new InvalidOperationException("owned Peer commit fixture failure"); }
            return ValueTask.FromResult(result);
        }
    }
}
