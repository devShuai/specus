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
using Specus.Server.PeerMesh;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

internal static class PeerManagementProviderProof
{
    internal static async Task VerifyAsync(TestServerFixture server)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var ct = timeout.Token;
        await using var writerScope = server.HostServices.CreateAsyncScope();
        await using var holderScope = server.HostServices.CreateAsyncScope();
        await using var deviceScope = server.HostServices.CreateAsyncScope();
        await using var aclScope = server.HostServices.CreateAsyncScope();
        await using var deletionScope = server.HostServices.CreateAsyncScope();
        await using var observerScope = server.HostServices.CreateAsyncScope();
        var services = writerScope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        var holder = holderScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var deviceDb = deviceScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var aclDb = aclScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var deletionDb = deletionScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var observer = observerScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        db.ManagementUsers.Add(new ManagementUser { Username = "native-peer-alice", LoginName = "alice", TenantId = "default", Enabled = true, PasswordHash = PasswordHasher.Hash("alice-password") });
        (await db.ManagementUsers.SingleAsync(u => u.Username == "bob-key", ct)).PasswordHash = PasswordHasher.Hash("bob-password");
        (await db.ClientAccounts.SingleAsync(c => c.Id == 1002, ct)).OwnerUsername = "alice";
        db.PeerMeshAcls.Add(new PeerMeshAcl { Id = 4801, TenantId = "default", OwnerUsername = "alice", SourceClientId = 1001, SourceClientName = "laptop", TargetClientId = 1002, TargetClientName = "offline", Allowed = true, Direction = "BOTH" });
        await db.SaveChangesAsync(ct);
        var admin = await OwnerTransferWriterProof.ActorAsync(server, services);
        var alice = await OwnerTransferWriterProof.ActorAsync(server, services, "alice", "alice-password");
        var bob = await OwnerTransferWriterProof.ActorAsync(server, services, "bob", "bob-password");
        foreach (var connection in new[] { db, holder, deviceDb, aclDb, deletionDb, observer }) await connection.Database.OpenConnectionAsync(ct);
        var postgres = db.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";
        var pidQuery = postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()";
        var writerPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(db, pidQuery, ct));
        var holderPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(holder, pidQuery, ct));
        var devicePid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(deviceDb, pidQuery, ct));
        var aclPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(aclDb, pidQuery, ct));
        var deletionPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(deletionDb, pidQuery, ct));
        var maria = Convert.ToString(await OwnerTransferWriterProof.ScalarAsync(observer, "SELECT VERSION()", ct))!.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        var preview = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(admin.Context, "501", ct);
        var device = deviceScope.ServiceProvider.GetRequiredService<PeerMeshService>();
        var acl = aclScope.ServiceProvider.GetRequiredService<PeerMeshService>();
        Task<OwnerTransferWriteOutcome>? transfer = null;
        Task<PeerMeshDeviceView>? update = null;
        Task<PeerMeshAclView>? upsert = null;
        await using (var hold = await holder.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct))
        {
            var released = false;
            try
            {
                await LockPeerAsync(holder, 801, ct);
                transfer = services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(admin, PathScope.CredentialGroup, "501",
                    OwnerTransferWriterProof.Body(PathScope.CredentialGroup, "bob", preview.Revision!), ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, writerPid, holderPid, postgres, maria, transfer, ct);
                update = device.UpdateDeviceAsync(alice.Context, 1001, new PeerMeshDeviceMutation(false), ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, devicePid, writerPid, postgres, maria, update, ct);
                upsert = acl.CreateAclAsync(alice.Context, new PeerMeshAclMutation(1001, 1002, false, "BOTH"), ct);
                // Same original actor: the ACL writer waits on the device writer's actor row,
                // which in turn waits on the transferring client. No sleeps or inferred order.
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, aclPid, devicePid, postgres, maria, upsert, ct);
                await hold.CommitAsync(ct); released = true;
                Assert.True((await transfer).Response.Changed);
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() => update);
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() => upsert);
            }
            finally
            {
                if (!released) await hold.RollbackAsync(CancellationToken.None);
                if (transfer is { IsCompleted: false } || update is { IsCompleted: false } || upsert is { IsCompleted: false })
                { timeout.Cancel(); if (transfer is not null) try { await transfer; } catch (Exception) { } if (update is not null) try { await update; } catch (Exception) { } if (upsert is not null) try { await upsert; } catch (Exception) { } }
            }
        }
        var storedDevice = await db.PeerMeshDevices.AsNoTracking().SingleAsync(p => p.Id == 801, ct);
        Assert.Equal("bob", storedDevice.OwnerUsername); Assert.True(storedDevice.Enabled);
        Assert.Equal("alice", (await db.PeerMeshAcls.AsNoTracking().SingleAsync(ct)).OwnerUsername);
        await device.UpdateDeviceAsync(bob.Context, 1001, new PeerMeshDeviceMutation(true), ct);
        await Assert.ThrowsAsync<ArgumentException>(() => acl.CreateAclAsync(bob.Context, new PeerMeshAclMutation(1001, 1002, false, "BOTH"), ct));
        await acl.DeleteAclAsync(alice.Context, 4801, ct);
        var ownAcl = await acl.CreateAclAsync(bob.Context, new PeerMeshAclMutation(1001, 1002, true, "BOTH"), ct);
        Assert.Equal("bob", (await db.PeerMeshAcls.AsNoTracking().SingleAsync(a => a.Id == ownAcl.Id, ct)).OwnerUsername);
        await acl.DeleteAclAsync(bob.Context, ownAcl.Id, ct);

        // Native string equality may use case-insensitive collations. A row selected by
        // SQL still needs exact tenant validation before any tracked refresh or mutation.
        db.ClientAccounts.Add(new ClientAccount { Id = 4004, TenantId = "default", OwnerUsername = "bob", ClientName = "peer-foreign-child", PasswordHash = "retained", Enabled = true });
        db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 804, TenantId = "DEFAULT", ClientId = 4004, ClientName = "peer-foreign-child", OwnerUsername = "bob", Enabled = true, VirtualIp = "10.66.0.8", Cidr = "10.66.0.0/16", PublicKey = "foreign-peer-key" });
        db.PeerMeshAcls.Add(new PeerMeshAcl { Id = 4804, TenantId = "DEFAULT", OwnerUsername = "bob", SourceClientId = 4004, SourceClientName = "peer-foreign-child", TargetClientId = 1001, TargetClientName = "laptop", Allowed = true, Direction = "BOTH" });
        await db.SaveChangesAsync(ct);
        await Assert.ThrowsAsync<ArgumentException>(() => device.UpdateDeviceAsync(bob.Context, 4004, new PeerMeshDeviceMutation(false), ct));
        var sqlMatches = await db.PeerMeshAcls.AsNoTracking().Where(a => a.TenantId == "default" && a.SourceClientId == 4004 && a.TargetClientId == 1001).ToListAsync(ct);
        if (sqlMatches.Count == 0)
        {
            // Exact tenant collations allow an independent default-tenant policy. The
            // foreign row must neither block this creation nor be modified by it.
            var independent = await acl.CreateAclAsync(bob.Context, new PeerMeshAclMutation(4004, 1001, false, "BOTH"), ct);
            Assert.NotEqual(4804, independent.Id);
            var stored = await db.PeerMeshAcls.AsNoTracking().SingleAsync(a => a.Id == independent.Id, ct);
            Assert.Equal("default", stored.TenantId); Assert.Equal("bob", stored.OwnerUsername); Assert.False(stored.Allowed);
            await acl.DeleteAclAsync(bob.Context, independent.Id, ct);
        }
        else
        {
            var foreign = Assert.Single(sqlMatches);
            Assert.Equal(4804, foreign.Id); Assert.Equal("DEFAULT", foreign.TenantId);
            await Assert.ThrowsAsync<ArgumentException>(() => acl.CreateAclAsync(bob.Context, new PeerMeshAclMutation(4004, 1001, false, "BOTH"), ct));
        }
        await Assert.ThrowsAsync<ArgumentException>(() => acl.DeleteAclAsync(bob.Context, 4804, ct));
        Assert.True((await db.PeerMeshDevices.AsNoTracking().SingleAsync(p => p.Id == 804, ct)).Enabled);
        Assert.True((await db.PeerMeshAcls.AsNoTracking().SingleAsync(a => a.Id == 4804, ct)).Allowed);

        db.ClientAccounts.Add(new ClientAccount { Id = 3003, TenantId = "default", OwnerUsername = "bob", ClientName = "peer-delete-parent", PasswordHash = "retained", Enabled = true });
        db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 803, TenantId = "default", ClientId = 3003, ClientName = "peer-delete-parent", OwnerUsername = "bob", Enabled = true, VirtualIp = "10.66.0.7", Cidr = "10.66.0.0/16", PublicKey = "delete-peer-key" });
        await db.SaveChangesAsync(ct);
        Task? deletion = null;
        Task<PeerMeshAclView>? creation = null;
        await using (var hold = await holder.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct))
        {
            var released = false;
            try
            {
                await LockPeerAsync(holder, 803, ct);
                deletion = deletionScope.ServiceProvider.GetRequiredService<ManagementMutationService>().DeleteClientAsync(admin.Context, 3003, ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, deletionPid, holderPid, postgres, maria, deletion, ct);
                // Request order is deliberately descending; implementation locks 1001 then 3003.
                creation = acl.CreateAclAsync(admin.Context, new PeerMeshAclMutation(3003, 1001, true, "BOTH"), ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, aclPid, deletionPid, postgres, maria, creation, ct);
                await hold.CommitAsync(ct); released = true;
                await deletion;
                await Assert.ThrowsAsync<ArgumentException>(() => creation);
                Assert.False(await db.ClientAccounts.AsNoTracking().AnyAsync(c => c.Id == 3003, ct));
                Assert.False(await db.PeerMeshAcls.AsNoTracking().AnyAsync(a => a.SourceClientId == 3003 || a.TargetClientId == 3003, ct));
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
