using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Networking;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

public sealed class PeerDefinitionBoundaryTests
{
    [Theory]
    [MemberData(nameof(PeerDefinitionOwnershipTests.Operations), MemberType = typeof(PeerDefinitionOwnershipTests))]
    public async Task ActualCommitFailureNeverPublishesUncommittedDefinitionsOrAudits(string operation)
    {
        var fault = new CommitFault { FailAt = operation == "import-tcp" ? 2 : 1 };
        await using var server = await StartAsync(fault);
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var actor = await ManagementResourceOwnershipTests.ContextAsync(server, services, "definition-operator", "operator-password");
        using var lifetime = new CancellationTokenSource();
        var writer = new RecordingWriter(); var bound = await BindAsync(server, writer, lifetime.Token);
        var auditBefore = services.GetRequiredService<PeerMeshServiceState>().Audits.Count;
        fault.Armed = true;
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => PeerDefinitionOwnershipTests.ChangeAsync(services.GetRequiredService<PeerMeshService>(), actor, operation));
            Assert.True(fault.Triggered); Assert.Equal(0, writer.Writes);
            Assert.Equal(auditBefore, services.GetRequiredService<PeerMeshServiceState>().Audits.Count);
            Assert.True((await db.PeerMeshServiceSharings.AsNoTracking().SingleAsync()).Enabled);
            Assert.True((await db.PeerMeshEgressSwitches.AsNoTracking().SingleAsync()).Enabled);
            Assert.Single(await db.PeerMeshSharedServices.AsNoTracking().ToListAsync());
            Assert.Equal(8080, (await db.PeerMeshSharedServices.AsNoTracking().SingleAsync()).TargetPort);
            Assert.False((await db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync()).Enabled);
            Assert.Equal("policy-manager", (await db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync()).OwnerUsername);
        }
        finally { server.HostServices.GetRequiredService<SessionRegistry>().Unbind("laptop", bound); lifetime.Cancel(); }
    }

    [Theory]
    [MemberData(nameof(PeerDefinitionOwnershipTests.Operations), MemberType = typeof(PeerDefinitionOwnershipTests))]
    public async Task RuntimeCallbacksObserveCommittedDefinitionsInIndependentContexts(string operation)
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        await SeedAsync(services.GetRequiredService<SpecusDbContext>());
        var actor = await ManagementResourceOwnershipTests.ContextAsync(server, services, "definition-operator", "operator-password");
        using var lifetime = new CancellationTokenSource();
        var writer = new RecordingWriter(async () =>
        {
            await using var observer = server.HostServices.CreateAsyncScope();
            var db = observer.ServiceProvider.GetRequiredService<SpecusDbContext>();
            switch (operation)
            {
                case "sharing": Assert.False((await db.PeerMeshServiceSharings.AsNoTracking().SingleAsync()).Enabled); break;
                case "egress-switch": Assert.False((await db.PeerMeshEgressSwitches.AsNoTracking().SingleAsync()).Enabled); break;
                case "service-create": case "import-tcp": Assert.Equal(2, await db.PeerMeshSharedServices.CountAsync()); break;
                case "service-update": Assert.Equal(8081, (await db.PeerMeshSharedServices.AsNoTracking().SingleAsync()).TargetPort); break;
                case "service-delete": Assert.Empty(await db.PeerMeshSharedServices.AsNoTracking().ToListAsync()); break;
                case "egress-upsert": Assert.True((await db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync()).Enabled); break;
                case "egress-delete": Assert.Empty(await db.PeerMeshEgressPolicies.AsNoTracking().ToListAsync()); break;
            }
        });
        var bound = await BindAsync(server, writer, lifetime.Token);
        try
        {
            await PeerDefinitionOwnershipTests.ChangeAsync(services.GetRequiredService<PeerMeshService>(), actor, operation);
            Assert.True(writer.Writes > 0);
            Assert.Null(services.GetRequiredService<SpecusDbContext>().Database.CurrentTransaction);
        }
        finally { server.HostServices.GetRequiredService<SessionRegistry>().Unbind("laptop", bound); lifetime.Cancel(); }
    }

    [Fact]
    public async Task RejectedServicePatchLeavesNoTrackedChangesForTheNextRequest()
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var actor = await ManagementResourceOwnershipTests.ContextAsync(server, services, "definition-operator", "operator-password");
        var peer = services.GetRequiredService<PeerMeshService>();
        await Assert.ThrowsAsync<ArgumentException>(() => peer.UpdateSharedServiceAsync(actor, 4901,
            new PeerMeshServiceMutation(null, null, "must-not-stick", null, null, null, null, 0, null, null, null, null), CancellationToken.None));
        Assert.False(db.ChangeTracker.HasChanges());
        Assert.Equal("existing", (await db.PeerMeshSharedServices.AsNoTracking().SingleAsync()).Name);
        await PeerDefinitionOwnershipTests.ChangeAsync(peer, actor, "service-update");
        Assert.Equal(8081, (await db.PeerMeshSharedServices.AsNoTracking().SingleAsync()).TargetPort);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ImportDoesNotDisguiseDatabaseFailureOrCancellationAsSkippedCandidates(bool cancelled)
    {
        var fault = new ImportFault { Cancelled = cancelled };
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true" },
            services => services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(fault)));
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var actor = await ManagementResourceOwnershipTests.ContextAsync(server, services, "definition-operator", "operator-password");
        fault.Armed = true;
        var peer = services.GetRequiredService<PeerMeshService>();
        if (cancelled) await Assert.ThrowsAsync<OperationCanceledException>(() => peer.ImportCandidatesAsync(actor, 1001, CancellationToken.None));
        else await Assert.ThrowsAsync<InvalidOperationException>(() => peer.ImportCandidatesAsync(actor, 1001, CancellationToken.None));
        Assert.True(fault.Triggered);
        Assert.Single(await db.PeerMeshSharedServices.AsNoTracking().ToListAsync());
    }

    private static Task<TestServerFixture> StartAsync(CommitFault? fault = null) => TestServerFixture.StartAsync(
        new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true" },
        fault is null ? null : services => services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(fault)));

    private static async Task SeedAsync(SpecusDbContext db)
    {
        await PeerDefinitionOwnershipTests.SeedAsync(db);
        (await db.ClientSessions.SingleAsync(session => session.Id == 901)).ClientEgressVersion = 1;
        await db.SaveChangesAsync();
    }

    private static async Task<SpecusConnectionContext> BindAsync(TestServerFixture server, IFrameWriter writer, CancellationToken lifetime)
    {
        var context = new SpecusConnectionContext("retained-control", "127.0.0.1:12345", writer, lifetime, () => { }, new ReadGate(lifetime), new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await db.ClientAccounts.AsNoTracking().SingleAsync(a => a.Id == 1001);
        await TestBoundPeerControl.PublishAsync(db, scope.ServiceProvider.GetRequiredService<Specus.Server.Authentication.ClientAuthSessionStore>(), account, context, 901);
        server.HostServices.GetRequiredService<SessionRegistry>().Replace("laptop", context);
        return context;
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
        internal int FailAt { get; init; } = 1;
        private int _commits;
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData eventData,
            InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (Armed && ++_commits == FailAt) { Triggered = true; throw new InvalidOperationException("owned definition commit fixture failure"); }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class ImportFault : SaveChangesInterceptor
    {
        internal bool Armed { get; set; }
        internal bool Cancelled { get; init; }
        internal bool Triggered { get; private set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Armed && eventData.Context!.ChangeTracker.Entries<PeerMeshSharedService>().Any(entry => entry.State == EntityState.Added))
            {
                Triggered = true;
                if (Cancelled) throw new OperationCanceledException("owned import cancellation fixture");
                throw new InvalidOperationException("owned import persistence fixture failure");
            }
            return ValueTask.FromResult(result);
        }
    }
}
