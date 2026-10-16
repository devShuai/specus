using System.Data;
using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;

namespace Specus.IntegrationTests;

internal static class PeerDefinitionProviderProof
{
    internal sealed class CommitGate : DbTransactionInterceptor
    {
        private Guid? _context;
        private TaskCompletionSource<bool> _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource<bool> _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task Entered => _entered.Task;
        internal void Arm(SpecusDbContext db)
        {
            _context = db.ContextId.InstanceId;
            _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        internal void Release() => _released.TrySetResult(true);
        public override async ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,
            TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (_context == eventData.Context?.ContextId.InstanceId)
            {
                _context = null;
                _entered.TrySetResult(true);
                await _released.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
    }

    internal static async Task VerifyAsync(TestServerFixture server, CommitGate gate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var ct = timeout.Token;
        await using var firstScope = server.HostServices.CreateAsyncScope();
        await using var secondScope = server.HostServices.CreateAsyncScope();
        await using var importScope = server.HostServices.CreateAsyncScope();
        await using var deletionScope = server.HostServices.CreateAsyncScope();
        await using var serviceScope = server.HostServices.CreateAsyncScope();
        await using var egressScope = server.HostServices.CreateAsyncScope();
        await using var holderScope = server.HostServices.CreateAsyncScope();
        await using var observerScope = server.HostServices.CreateAsyncScope();
        var services = firstScope.ServiceProvider;
        var firstDb = services.GetRequiredService<SpecusDbContext>();
        var secondDb = secondScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var importDb = importScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var deletionDb = deletionScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var serviceDb = serviceScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var egressDb = egressScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var holder = holderScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var observer = observerScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(firstDb, "default");
        var admin = await OwnerTransferWriterProof.ActorAsync(server, services);
        foreach (var db in new[] { firstDb, secondDb, importDb, deletionDb, serviceDb, egressDb, holder, observer }) await db.Database.OpenConnectionAsync(ct);
        var postgres = firstDb.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";
        var pidQuery = postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()";
        async Task<long> PidAsync(SpecusDbContext db) => Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(db, pidQuery, ct));
        var firstPid = await PidAsync(firstDb); var secondPid = await PidAsync(secondDb); var importPid = await PidAsync(importDb);
        var deletionPid = await PidAsync(deletionDb); var servicePid = await PidAsync(serviceDb); var egressPid = await PidAsync(egressDb); var holderPid = await PidAsync(holder);
        var maria = Convert.ToString(await OwnerTransferWriterProof.ScalarAsync(observer, "SELECT VERSION()", ct))!.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        var first = services.GetRequiredService<PeerMeshService>();
        var second = secondScope.ServiceProvider.GetRequiredService<PeerMeshService>();
        Assert.False(await firstDb.PeerMeshServiceSharings.AnyAsync(ct));
        await ObserveRaceAsync(() => first.SetSharingAsync(admin.Context, new PeerMeshSharingMutation(true, null), ct),
            () => second.SetSharingAsync(admin.Context, new PeerMeshSharingMutation(null, true), ct),
            firstDb, gate, observer, secondPid, firstPid, postgres, maria, false, ct);
        var sharing = await observer.PeerMeshServiceSharings.AsNoTracking().SingleAsync(ct);
        Assert.True(sharing.Enabled); Assert.True(sharing.MdnsImportEnabled);
        Assert.False(await firstDb.PeerMeshEgressSwitches.AnyAsync(ct));
        await ObserveRaceAsync(() => first.SetEgressSwitchAsync(admin.Context, true, ct),
            () => second.SetEgressSwitchAsync(admin.Context, false, ct),
            firstDb, gate, observer, secondPid, firstPid, postgres, maria, false, ct);
        Assert.False((await observer.PeerMeshEgressSwitches.AsNoTracking().SingleAsync(ct)).Enabled);

        var now = DateTimeOffset.UtcNow;
        services.GetRequiredService<PeerMeshServiceState>().ServiceCatalogs[("default", 1001, 901)] = new PeerMeshServiceCatalogSnapshot(
            1, "definition-mdns", now, now.AddHours(1), [], "laptop", [],
            [new PeerMdnsCandidate { Name = "mdns-web", Transport = "tcp", Application = "http", TargetHost = "127.0.0.1", TargetPort = 18082 }]);
        // The importer reads the old enabled flag, then waits at the actual creation boundary
        // on a real management disable transaction. Its reread must reject, not count a skip.
        await ObserveRaceAsync(() => first.SetSharingAsync(admin.Context, new PeerMeshSharingMutation(null, false), ct),
            () => importScope.ServiceProvider.GetRequiredService<PeerMeshService>().ImportCandidatesAsync(admin.Context, 1001, "mdns", ct),
            firstDb, gate, observer, importPid, firstPid, postgres, maria, true, ct);
        Assert.False((await observer.PeerMeshServiceSharings.AsNoTracking().SingleAsync(ct)).MdnsImportEnabled);
        Assert.Empty(await observer.PeerMeshSharedServices.AsNoTracking().ToListAsync(ct));
        await VerifyDeletedParentAsync(server, admin.Context, deletionScope.ServiceProvider, serviceScope.ServiceProvider,
            egressScope.ServiceProvider, firstDb, holder, observer, deletionPid, servicePid, egressPid, holderPid, postgres, maria, ct);
    }

    private static async Task ObserveRaceAsync(Func<Task> startFirst, Func<Task> startSecond, SpecusDbContext firstDb,
        CommitGate gate, SpecusDbContext observer, long secondPid, long firstPid, bool postgres, bool maria, bool secondRejects, CancellationToken ct)
    {
        Task? first = null; Task? second = null;
        gate.Arm(firstDb);
        try
        {
            first = startFirst();
            await Task.WhenAny(first, gate.Entered).WaitAsync(ct);
            if (!gate.Entered.IsCompleted) { await first; throw new InvalidOperationException("actual management writer did not reach its commit gate"); }
            await gate.Entered;
            second = startSecond();
            await OwnerTransferWriterProof.WaitForBlockerAsync(observer, secondPid, firstPid, postgres, maria, second, ct);
            gate.Release();
            await first;
            if (secondRejects) await Assert.ThrowsAsync<InvalidOperationException>(() => second);
            else await second;
        }
        finally
        {
            gate.Release();
            if (first is not null) try { await first; } catch (Exception) { }
            if (second is not null) try { await second; } catch (Exception) { }
        }
    }

    private static async Task VerifyDeletedParentAsync(TestServerFixture server, ManagementContext admin,
        IServiceProvider deletionServices, IServiceProvider serviceServices, IServiceProvider egressServices,
        SpecusDbContext db, SpecusDbContext holder, SpecusDbContext observer, long deletionPid, long servicePid, long egressPid,
        long holderPid, bool postgres, bool maria, CancellationToken ct)
    {
        Task? deletion = null; Task<PeerMeshSharedServiceView>? service = null; Task<PeerMeshEgressPolicyView>? policy = null;
        await using var hold = await holder.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        var released = false;
        try
        {
            var entity = db.Model.FindEntityType(typeof(PeerMeshDevice))!;
            var table = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
            var sql = db.GetService<ISqlGenerationHelper>(); var key = sql.DelimitIdentifier(entity.FindProperty("Id")!.GetColumnName(table)!);
            _ = await OwnerTransferWriterProof.ScalarAsync(holder, $"SELECT {key} FROM {sql.DelimitIdentifier(table.Name, table.Schema)} WHERE {key}=@id FOR UPDATE", ct, ("@id", 801L));
            deletion = deletionServices.GetRequiredService<ManagementMutationService>().DeleteClientAsync(admin, 1001, ct);
            await OwnerTransferWriterProof.WaitForBlockerAsync(observer, deletionPid, holderPid, postgres, maria, deletion, ct);
            service = serviceServices.GetRequiredService<PeerMeshService>().CreateSharedServiceAsync(admin,
                new PeerMeshServiceMutation(1001, "new-service-01", "new", "", "tcp", "http", "127.0.0.1", 8081, 18081, "/", false, "OWNER"), ct);
            await OwnerTransferWriterProof.WaitForBlockerAsync(observer, servicePid, deletionPid, postgres, maria, service, ct);
            policy = egressServices.GetRequiredService<PeerMeshService>().UpsertEgressPolicyAsync(admin, new PeerEgressPolicyMutation(EgressClientId: 1001, Enabled: true), ct);
            await OwnerTransferWriterProof.WaitForBlockerAsync(observer, egressPid, postgres ? servicePid : deletionPid, postgres, maria, policy, ct);
            if (postgres)
            {
                // PostgreSQL queues the second waiter behind the first waiter's tuple lock.
                // Both must concern the actual parent row, not merely an arbitrary wait chain.
                var clientEntity = db.Model.FindEntityType(typeof(ClientAccount))!;
                var clientStore = StoreObjectIdentifier.Table(clientEntity.GetTableName()!, clientEntity.GetSchema());
                var clientTable = sql.DelimitIdentifier(clientStore.Name, clientStore.Schema);
                var clientKey = sql.DelimitIdentifier(clientEntity.FindProperty("Id")!.GetColumnName(clientStore)!);
                var parentTupleLock = $"""
                    SELECT COUNT(*) FROM pg_locks l JOIN {clientTable} a
                      ON a.ctid::text='(' || l.page::text || ',' || l.tuple::text || ')'
                    WHERE l.pid=@pid AND l.locktype='tuple' AND l.granted=@granted
                      AND l.relation=to_regclass(@relation) AND a.{clientKey}=@client
                    """;
                Assert.Equal(1, Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(observer, parentTupleLock, ct, ("@pid", servicePid), ("@granted", true), ("@relation", clientTable), ("@client", 1001L))));
                Assert.Equal(1, Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(observer, parentTupleLock, ct, ("@pid", egressPid), ("@granted", false), ("@relation", clientTable), ("@client", 1001L))));
            }
            await hold.CommitAsync(ct); released = true;
            await deletion;
            await Assert.ThrowsAsync<ArgumentException>(() => service);
            await Assert.ThrowsAsync<ResourceNotFoundException>(() => policy);
            Assert.False(await db.ClientAccounts.AsNoTracking().AnyAsync(client => client.Id == 1001, ct));
            Assert.False(await db.PeerMeshSharedServices.AsNoTracking().AnyAsync(row => row.ClientId == 1001, ct));
            Assert.False(await db.PeerMeshEgressPolicies.AsNoTracking().AnyAsync(row => row.EgressClientId == 1001, ct));
        }
        finally
        {
            if (!released) await hold.RollbackAsync(CancellationToken.None);
            foreach (var task in new Task?[] { deletion, service, policy }) if (task is not null) try { await task; } catch (Exception) { }
        }
    }
}
