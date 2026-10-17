using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

internal static class ManagementUserActorProviderProof
{
    internal static async Task VerifyAsync(TestServerFixture server)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var ct = timeout.Token;
        await using var seedScope = server.HostServices.CreateAsyncScope();
        await using var holderScope = server.HostServices.CreateAsyncScope();
        await using var firstScope = server.HostServices.CreateAsyncScope();
        await using var secondScope = server.HostServices.CreateAsyncScope();
        await using var observerScope = server.HostServices.CreateAsyncScope();
        var seed = seedScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var holder = holderScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var firstDb = firstScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var secondDb = secondScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var observer = observerScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var password = PasswordHasher.Hash("actor-password");
        seed.ManagementUsers.AddRange(
            User("a-operator-key", "operator", password), User("z-target-key", "target", password),
            User("a-admin-key", "low-admin", password), User("z-admin-key", "high-admin", password));
        await seed.SaveChangesAsync(ct);
        var original = await OwnerTransferWriterProof.ActorAsync(server, seedScope.ServiceProvider, "operator", "actor-password");
        var low = await OwnerTransferWriterProof.ActorAsync(server, seedScope.ServiceProvider, "low-admin", "actor-password");
        var high = await OwnerTransferWriterProof.ActorAsync(server, seedScope.ServiceProvider, "high-admin", "actor-password");
        foreach (var db in new[] { holder, firstDb, secondDb, observer }) await db.Database.OpenConnectionAsync(ct);
        var postgres = firstDb.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";
        var pidSql = postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()";
        var holderPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(holder, pidSql, ct));
        var firstPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(firstDb, pidSql, ct));
        var secondPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(secondDb, pidSql, ct));
        var maria = Convert.ToString(await OwnerTransferWriterProof.ScalarAsync(observer, "SELECT VERSION()", ct))!.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        Task<ManagementUserView>? first = null;
        await using (var hold = await holder.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct))
        {
            var released = false;
            try
            {
                await holder.Database.ExecuteSqlInterpolatedAsync($"UPDATE specus_management_user SET enabled={false} WHERE username={"a-operator-key"}", ct);
                first = firstScope.ServiceProvider.GetRequiredService<ManagementUserService>().UpdateUserAsync(original.Context, "target",
                    new UserMutation(null, null, null, false), ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, firstPid, holderPid, postgres, maria, first, ct);
                await hold.CommitAsync(ct); released = true;
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() => first);
                Assert.True((await seed.ManagementUsers.AsNoTracking().SingleAsync(u => u.Username == "z-target-key", ct)).Enabled);
            }
            finally
            {
                if (!released) await hold.RollbackAsync(CancellationToken.None);
                if (first is { IsCompleted: false }) { timeout.Cancel(); try { await first; } catch (Exception) { } }
            }
        }
        // Both requests must reach the same lowest account-key lock first. Actor-first ordering
        // would let the high actor hold the upper key, producing an opposite-order cycle later.
        first = null;
        Task<ManagementUserView>? second = null;
        await using (var hold = await holder.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct))
        {
            var released = false;
            try
            {
                _ = await OwnerTransferWriterProof.ScalarAsync(holder, "SELECT username FROM specus_management_user WHERE username=@key FOR UPDATE", ct, ("@key", "a-admin-key"));
                first = firstScope.ServiceProvider.GetRequiredService<ManagementUserService>().UpdateUserAsync(low.Context, "high-admin",
                    new UserMutation(null, "changed-high-password", null, null), ct);
                // Starting an async request does not prove it reached PostgreSQL's tuple
                // queue before the next request. Establish that real blocking edge first;
                // both operations still overlap while the holder keeps the LOW row locked.
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, firstPid, holderPid, postgres, maria, first, ct);
                second = secondScope.ServiceProvider.GetRequiredService<ManagementUserService>().UpdateUserAsync(high.Context, "low-admin",
                    new UserMutation(null, "changed-low-password", null, null), ct);
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, firstPid, holderPid, postgres, maria, first, ct);
                // PostgreSQL queues later tuple lockers behind the first waiter: the real chain
                // is second -> first -> holder. Verify the actual tuple is the LOW account row,
                // not a higher row already held in an incorrectly reversed account-key order.
                await OwnerTransferWriterProof.WaitForBlockerAsync(observer, secondPid, postgres ? firstPid : holderPid, postgres, maria, second, ct);
                if (postgres)
                {
                    const string tupleAtLowRow = """
                        SELECT COUNT(*) FROM pg_locks l JOIN specus_management_user u
                          ON u.ctid::text='(' || l.page::text || ',' || l.tuple::text || ')'
                        WHERE l.pid=@pid AND l.locktype='tuple' AND l.granted=@granted
                          AND l.relation='specus_management_user'::regclass AND u.username=@key
                        """;
                    Assert.Equal(1, Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(observer, tupleAtLowRow, ct,
                        ("@pid", firstPid), ("@granted", true), ("@key", "a-admin-key"))));
                    Assert.Equal(1, Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(observer, tupleAtLowRow, ct,
                        ("@pid", secondPid), ("@granted", false), ("@key", "a-admin-key"))));
                }
                await hold.CommitAsync(ct); released = true;
                Assert.True((await first).Enabled); Assert.True((await second).Enabled);
                Assert.True(PasswordHasher.Matches("changed-high-password", (await seed.ManagementUsers.AsNoTracking().SingleAsync(u => u.Username == "z-admin-key", ct)).PasswordHash));
                Assert.True(PasswordHasher.Matches("changed-low-password", (await seed.ManagementUsers.AsNoTracking().SingleAsync(u => u.Username == "a-admin-key", ct)).PasswordHash));
            }
            finally
            {
                if (!released) await hold.RollbackAsync(CancellationToken.None);
                if (first is { IsCompleted: false } || second is { IsCompleted: false })
                {
                    timeout.Cancel();
                    if (first is not null) try { await first; } catch (Exception) { }
                    if (second is not null) try { await second; } catch (Exception) { }
                }
            }
        }
    }

    private static ManagementUser User(string key, string name, string password) => new()
    { Username = key, LoginName = name, TenantId = "default", Role = ManagementRole.Admin, Enabled = true, PasswordHash = password };
}
