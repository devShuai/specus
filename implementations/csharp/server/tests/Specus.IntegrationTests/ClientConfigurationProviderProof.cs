using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

internal static class ClientConfigurationProviderProof
{
    internal static async Task VerifyAsync(TestServerFixture server)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var ct = timeout.Token;
        await using var writerScope = server.HostServices.CreateAsyncScope();
        await using var holderScope = server.HostServices.CreateAsyncScope();
        await using var mutationScope = server.HostServices.CreateAsyncScope();
        await using var deletionScope = server.HostServices.CreateAsyncScope();
        await using var observerScope = server.HostServices.CreateAsyncScope();
        var services = writerScope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        var holder = holderScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var mutationDb = mutationScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var deletionDb = deletionScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var observer = observerScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        db.ManagementUsers.Add(new ManagementUser { Username = "config-alice", LoginName = "alice", TenantId = "default", Enabled = true, PasswordHash = PasswordHasher.Hash("alice-password") });
        (await db.ManagementUsers.SingleAsync(u => u.Username == "bob-key", ct)).PasswordHash = PasswordHasher.Hash("bob-password");
        db.SpecusMappings.Add(new SpecusMapping { Id = 4201, TenantId = "default", ClientId = 1001, ClientName = "laptop", ListenPort = 24861, TargetAddress = "127.0.0.1", TargetPort = 80, Enabled = false });
        db.HttpRouteMappings.Add(new HttpRouteMapping { Id = 4301, TenantId = "default", ClientId = 1001, ClientName = "laptop", Route = "existing", TargetBaseUrl = "http://127.0.0.1:8000", Enabled = false });
        await db.SaveChangesAsync(ct);
        var admin = await OwnerTransferWriterProof.ActorAsync(server, services);
        var alice = await OwnerTransferWriterProof.ActorAsync(server, services, "alice", "alice-password");
        var bob = await OwnerTransferWriterProof.ActorAsync(server, services, "bob", "bob-password");
        foreach (var connection in new[] { db, holder, mutationDb, deletionDb, observer }) await connection.Database.OpenConnectionAsync(ct);
        var postgres = db.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";
        var query = postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()";
        var writerPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(db, query, ct));
        var holderPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(holder, query, ct));
        var mutationPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(mutationDb, query, ct));
        var deletionPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(deletionDb, query, ct));
        var maria = Convert.ToString(await OwnerTransferWriterProof.ScalarAsync(observer, "SELECT VERSION()", ct))!.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        var preview = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(admin.Context, "501", ct);
        var mutation = mutationScope.ServiceProvider.GetRequiredService<ManagementMutationService>();
        Task<OwnerTransferWriteOutcome>? transfer = null;
        Task<SpecusMappingView>? update = null;
        await using (var hold = await holder.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct))
        {
            var released = false;
            try
            {
                await LockPeerAsync(holder, 801, ct);
                transfer = services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(admin, PathScope.CredentialGroup, "501",
                    OwnerTransferWriterProof.Body(PathScope.CredentialGroup, "bob", preview.Revision!), ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, writerPid, holderPid, postgres, maria, transfer, ct);
                update = mutation.UpdateSpecusAsync(alice.Context, 4201, new SpecusMappingMutation(24861, "127.0.0.1", 81, false, false), ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, mutationPid, writerPid, postgres, maria, update, ct);
                await hold.CommitAsync(ct); released = true;
                Assert.True((await transfer).Response.Changed);
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() => update);
                Assert.Equal(80, (await db.SpecusMappings.AsNoTracking().SingleAsync(m => m.Id == 4201, ct)).TargetPort);
            }
            finally
            {
                if (!released) await hold.RollbackAsync(CancellationToken.None);
                if (transfer is { IsCompleted: false } || update is { IsCompleted: false })
                { timeout.Cancel(); if (transfer is not null) try { await transfer; } catch (Exception) { } if (update is not null) try { await update; } catch (Exception) { } }
            }
        }
        // The new owner can perform all six ordinary configuration operations on the real provider.
        Assert.Equal(81, (await mutation.UpdateSpecusAsync(bob.Context, 4201, new SpecusMappingMutation(24861, "127.0.0.1", 81, false, false), ct)).TargetPort);
        var mapping = await mutation.CreateSpecusAsync(bob.Context, 1001, new SpecusMappingMutation(24862, "127.0.0.1", 82, false, false), ct);
        await mutation.DeleteSpecusAsync(bob.Context, mapping.Id, ct);
        Assert.Equal("http://127.0.0.1:8001", (await mutation.UpdateHttpRouteAsync(bob.Context, 4301,
            new HttpRouteMutation("existing", "http://127.0.0.1:8001", false, false, false, false, null, null), ct)).TargetBaseUrl);
        var route = await mutation.CreateHttpRouteAsync(bob.Context, 1001, new HttpRouteMutation("new-route", "http://127.0.0.1:8002", false, false, false, false, null, null), ct);
        await mutation.DeleteHttpRouteAsync(bob.Context, route.Id, ct);
        Assert.Equal(1, await db.SpecusMappings.CountAsync(m => m.ClientId == 1001, ct));
        Assert.Equal(1, await db.HttpRouteMappings.CountAsync(r => r.ClientId == 1001, ct));
        db.ClientAccounts.Add(new ClientAccount { Id = 3003, TenantId = "default", OwnerUsername = "bob", ClientName = "config-delete-parent", PasswordHash = "retained", Enabled = true });
        db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 803, TenantId = "default", ClientId = 3003, ClientName = "config-delete-parent", OwnerUsername = "bob", Enabled = false, VirtualIp = "10.66.0.7", Cidr = "10.66.0.0/16", PublicKey = "delete-parent-public-key" });
        await db.SaveChangesAsync(ct);
        Task? deletion = null;
        Task<SpecusMappingView>? creation = null;
        await using (var hold = await holder.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct))
        {
            var released = false;
            try
            {
                await LockPeerAsync(holder, 803, ct);
                deletion = deletionScope.ServiceProvider.GetRequiredService<ManagementMutationService>().DeleteClientAsync(admin.Context, 3003, ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, deletionPid, holderPid, postgres, maria, deletion, ct);
                creation = mutation.CreateSpecusAsync(admin.Context, 3003, new SpecusMappingMutation(24863, "127.0.0.1", 83, false, false), ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, mutationPid, deletionPid, postgres, maria, creation, ct);
                await hold.CommitAsync(ct); released = true;
                await deletion;
                await Assert.ThrowsAsync<ArgumentException>(() => creation);
                Assert.False(await db.ClientAccounts.AsNoTracking().AnyAsync(c => c.Id == 3003, ct));
                Assert.False(await db.SpecusMappings.AsNoTracking().AnyAsync(m => m.ClientId == 3003, ct));
                Assert.False(await db.PeerMeshDevices.AsNoTracking().AnyAsync(p => p.Id == 803, ct));
                Assert.Equal(1, await db.ClientOwnerTransferAudits.CountAsync(ct));
                Assert.Equal("NETTY_ONLINE", (await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == 901, ct)).Status);
            }
            finally
            {
                if (!released) await hold.RollbackAsync(CancellationToken.None);
                if (deletion is { IsCompleted: false } || creation is { IsCompleted: false })
                { timeout.Cancel(); if (deletion is not null) try { await deletion; } catch (Exception) { } if (creation is not null) try { await creation; } catch (Exception) { } }
            }
        }
    }

    private static async Task LockPeerAsync(SpecusDbContext db, long id, CancellationToken ct)
    {
        var entity = db.Model.FindEntityType(typeof(PeerMeshDevice))!;
        var table = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
        var sql = db.GetService<ISqlGenerationHelper>();
        var key = sql.DelimitIdentifier(entity.FindProperty("Id")!.GetColumnName(table)!);
        _ = await OwnerTransferWriterProof.ScalarAsync(db, $"SELECT {key} FROM {sql.DelimitIdentifier(table.Name, table.Schema)} WHERE {key}=@id FOR UPDATE", ct, ("@id", id));
    }
}
