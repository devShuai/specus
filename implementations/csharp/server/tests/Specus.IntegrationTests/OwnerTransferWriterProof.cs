using System.Net;
using System.Net.Http.Json;
using System.Data;
using System.Data.Common;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

// Same actual bearer + write/readback assertions, compiled into all mandatory provider projects.
internal static class OwnerTransferWriterProof
{
    internal static async Task VerifyNativeTargetOrderingAsync(TestServerFixture server)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var ct = timeout.Token;
        await using var writerScope = server.HostServices.CreateAsyncScope();
        await using var holderScope = server.HostServices.CreateAsyncScope();
        await using var observerScope = server.HostServices.CreateAsyncScope();
        var services = writerScope.ServiceProvider;
        var writerDb = services.GetRequiredService<SpecusDbContext>();
        var holderDb = holderScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var observer = observerScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var postgres = writerDb.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";
        Assert.True(postgres || writerDb.Database.ProviderName == "MySql.EntityFrameworkCore");
        var actor = await ActorAsync(server, services);
        await SeedAsync(writerDb, actor.Context.TenantId);
        await SeedTicketsAsync(writerDb, actor.Context.TenantId);
        await writerDb.Database.OpenConnectionAsync(ct); await holderDb.Database.OpenConnectionAsync(ct); await observer.Database.OpenConnectionAsync(ct);
        var writerPid = Convert.ToInt64(await ScalarAsync(writerDb, postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()", ct));
        var holderPid = Convert.ToInt64(await ScalarAsync(holderDb, postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()", ct));
        var version = Convert.ToString(await ScalarAsync(observer, "SELECT VERSION()", ct))!;
        var maria = version.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        var preview = await PreviewAsync(services, actor, PathScope.CredentialGroup, 501);
        var writer = services.GetRequiredService<ClientOwnerTransferWriter>();
        Task<OwnerTransferWriteOutcome>? pending = null;
        // The initial ordinary target lookup sees the old enabled row. Its real FOR UPDATE
        // then waits on an uncommitted disable, and must reload the committed disabled row.
        await using (var hold = await holderDb.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct))
        {
            var released = false;
            try
            {
                await ExecuteAsync(holderDb, "UPDATE specus_management_user SET enabled=@enabled WHERE username=@key",
                    ct, ("@enabled", false), ("@key", "bob-key"));
                pending = writer.CommitAsync(actor, PathScope.CredentialGroup, "501", Body(PathScope.CredentialGroup, "bob", preview.Revision!), ct);
                await WaitForBlockerAsync(observer, writerPid, holderPid, postgres, maria, pending, ct);
                await hold.CommitAsync(ct);
                released = true;
                var denied = await Assert.ThrowsAsync<ClientOwnerTransferException>(() => pending);
                Assert.Equal("INVALID_TARGET_OWNER", denied.Code);
                Assert.Equal(0, await writerDb.ClientOwnerTransferAudits.CountAsync(ct));
                Assert.Equal("alice", (await writerDb.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501, ct)).OwnerUsername);
            }
            finally
            {
                if (!released) await hold.RollbackAsync(CancellationToken.None);
                if (pending is { IsCompleted: false }) { timeout.Cancel(); try { await pending; } catch (Exception) { } }
            }
        }
        await ExecuteAsync(holderDb, "UPDATE specus_management_user SET enabled=@enabled WHERE username=@key", ct, ("@enabled", true), ("@key", "bob-key"));
        await using var updateScope = server.HostServices.CreateAsyncScope();
        var updateDb = updateScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await updateDb.Database.OpenConnectionAsync(ct);
        var updatePid = Convert.ToInt64(await ScalarAsync(updateDb, postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()", ct));
        Task? update = null;
        pending = null;
        // Blocking the credential is AFTER the writer's ordered target lock. A real ordinary
        // management disable must now wait on the writer, not overtake its successful commit.
        await using (var hold = await holderDb.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct))
        {
            var released = false;
            try
            {
                var entity = holderDb.Model.FindEntityType(typeof(ClientCredential))!;
                var table = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
                var sql = holderDb.GetService<ISqlGenerationHelper>();
                var key = sql.DelimitIdentifier(entity.FindProperty("Id")!.GetColumnName(table)!);
                _ = await ScalarAsync(holderDb, $"SELECT {key} FROM {sql.DelimitIdentifier(table.Name, table.Schema)} WHERE {key}=501 FOR UPDATE", ct);
                pending = writer.CommitAsync(actor, PathScope.CredentialGroup, "501", Body(PathScope.CredentialGroup, "bob", preview.Revision!), ct);
                await WaitForBlockerAsync(observer, writerPid, holderPid, postgres, maria, pending, ct);
                update = updateScope.ServiceProvider.GetRequiredService<ManagementUserService>().UpdateUserAsync(actor.Context,
                    "bob", new UserMutation(null, null, null, false), ct);
                await WaitForBlockerAsync(observer, updatePid, writerPid, postgres, maria, update, ct);
                Assert.False(update.IsCompleted);
                await hold.CommitAsync(ct);
                released = true;
                Assert.True((await pending).Response.Changed);
                await update;
                Assert.False((await writerDb.ManagementUsers.AsNoTracking().SingleAsync(u => u.Username == "bob-key", ct)).Enabled);
                Assert.Equal("bob", (await writerDb.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501, ct)).OwnerUsername);
                Assert.Equal(1, await writerDb.ClientOwnerTransferAudits.CountAsync(ct));
                await AssertRetainedTicketsAsync(writerDb);
            }
            finally
            {
                if (!released) await hold.RollbackAsync(CancellationToken.None);
                if (pending is { IsCompleted: false } || update is { IsCompleted: false })
                {
                    timeout.Cancel();
                    if (pending is not null) try { await pending; } catch (Exception) { }
                    if (update is not null) try { await update; } catch (Exception) { }
                }
            }
        }
    }

    private static async Task WaitForBlockerAsync(SpecusDbContext observer, long waiter, long holder, bool postgres, bool maria, Task operation, CancellationToken ct)
    {
        var query = postgres ? "SELECT COUNT(*) FROM pg_stat_activity WHERE pid=@waiter AND @holder=ANY(pg_blocking_pids(pid))"
            : maria ? "SELECT COUNT(*) FROM information_schema.INNODB_LOCK_WAITS w JOIN information_schema.INNODB_TRX r ON r.trx_id=w.requesting_trx_id JOIN information_schema.INNODB_TRX b ON b.trx_id=w.blocking_trx_id WHERE r.trx_mysql_thread_id=@waiter AND b.trx_mysql_thread_id=@holder"
            : "SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.threads r ON r.THREAD_ID=w.REQUESTING_THREAD_ID JOIN performance_schema.threads b ON b.THREAD_ID=w.BLOCKING_THREAD_ID WHERE r.PROCESSLIST_ID=@waiter AND b.PROCESSLIST_ID=@holder";
        var timer = Stopwatch.StartNew();
        var engine = postgres ? "postgres" : Convert.ToString(await ScalarAsync(observer,
            "SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='specus_management_user'", ct));
        // MariaDB 11.4.5 trx0i_s.cc CACHE_MIN_IDLE_TIME_NS requires >100ms since
        // the LAST READ, not last refresh. Faster polling pins a stale snapshot.
        // Also idle before the first read: the same backend pair can have a new wait.
        // Keep the original 10s deadline and exact waiter->holder assertion.
        if (maria) await Task.Delay(150, ct);
        while (timer.Elapsed < TimeSpan.FromSeconds(10))
        {
            if (Convert.ToInt64(await ScalarAsync(observer, query, ct, ("@waiter", waiter), ("@holder", holder))) > 0) return;
            if (operation.IsCompleted)
            {
                var error = await Record.ExceptionAsync(() => operation);
                Assert.Fail($"operation completed before observed database blocking edge; engine={engine}; waiter={waiter}; holder={holder}; result={error?.GetType().Name}:{error?.Message}");
            }
            await Task.Delay(maria ? 150 : 10, ct);
        }
        var state = postgres ? "postgres" : Convert.ToString(await ScalarAsync(observer,
            "SELECT STATE FROM information_schema.PROCESSLIST WHERE ID=@waiter", ct, ("@waiter", waiter)));
        var waits = maria ? await ScalarAsync(observer, "SELECT COUNT(*) FROM information_schema.INNODB_LOCK_WAITS", ct) : null;
        var diagnostic = "";
        if (maria)
        {
            await using (var command = CreateCommand(observer, "SELECT ID,STATE,LEFT(INFO,500) FROM information_schema.PROCESSLIST WHERE ID IN (@waiter,@holder)", [("@waiter", waiter), ("@holder", holder)]))
            await using (var rows = await command.ExecuteReaderAsync(ct))
                while (await rows.ReadAsync(ct)) diagnostic += $" process={rows.GetValue(0)}/{rows.GetValue(1)}/{rows.GetValue(2)};";
            await using var status = CreateCommand(observer, "SHOW ENGINE INNODB STATUS", []);
            await using var reader = await status.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                var text = reader.GetString(2); var start = text.IndexOf("TRANSACTIONS", StringComparison.Ordinal);
                if (start >= 0) diagnostic += text.Substring(start, Math.Min(4000, text.Length - start));
            }
        }
        Assert.Fail($"did not observe the expected real database blocking edge; engine={engine}; waiter={waiter}; holder={holder}; processState={state}; waitRows={waits}; operation={operation.Status}; {diagnostic}");
    }

    private static async Task<object?> ScalarAsync(SpecusDbContext db, string text, CancellationToken ct, params (string, object)[] parameters)
    {
        await using var command = CreateCommand(db, text, parameters);
        return await command.ExecuteScalarAsync(ct);
    }

    private static async Task ExecuteAsync(SpecusDbContext db, string text, CancellationToken ct, params (string, object)[] parameters)
    {
        await using var command = CreateCommand(db, text, parameters);
        _ = await command.ExecuteNonQueryAsync(ct);
    }

    private static DbCommand CreateCommand(SpecusDbContext db, string text, (string Name, object Value)[] parameters)
    {
        var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction(); command.CommandText = text;
        foreach (var (name, value) in parameters) { var parameter = command.CreateParameter(); parameter.ParameterName = name; parameter.Value = value; command.Parameters.Add(parameter); }
        return command;
    }

    internal static async Task<OwnerTransferActor> ActorAsync(TestServerFixture server, IServiceProvider services)
    {
        var auth = services.GetRequiredService<IOptions<AuthOptions>>().Value;
        using var client = server.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/login", new AdminLoginRequest(auth.Username, auth.Password, TenantId: auth.TenantId));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var token = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString();
        var principal = await services.GetRequiredService<AdminBearerTokenValidator>().ValidateAsync(token);
        Assert.NotNull(principal);
        return OwnerTransferActor.From(new DefaultHttpContext { User = principal }, auth);
    }

    internal static async Task SeedTicketsAsync(SpecusDbContext db, string tenant)
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (hash, scope, owner, ticketTenant) in new[]
        {
            ("removed-events", WebSocketTicketService.ConnectionsScope, "bob", tenant),
            ("removed-messages", WebSocketTicketService.ClientMessagesScope, "bob", tenant),
            ("retained-public", WebSocketTicketService.PublicTransferScope, "bob", tenant),
            ("retained-foreign", WebSocketTicketService.ConnectionsScope, "bob", tenant + "-foreign"),
            ("retained-other", WebSocketTicketService.ClientMessagesScope, "carol", tenant),
        }) db.WebSocketTickets.Add(new WebSocketTicket { TokenHash = hash, Scope = scope, Username = owner, TenantId = ticketTenant, CreatedAt = now, ExpiresAt = now.AddHours(1) });
        await db.SaveChangesAsync();
    }

    internal static async Task AssertRetainedTicketsAsync(SpecusDbContext db) => Assert.Equal(
        new[] { "retained-foreign", "retained-other", "retained-public" },
        await db.WebSocketTickets.AsNoTracking().OrderBy(t => t.TokenHash).Select(t => t.TokenHash).ToArrayAsync());

    internal static JsonElement Body(PathScope scope, string target, string revision) =>
        JsonSerializer.SerializeToElement(new { scope = scope.WireName(), targetUsername = target, expectedRevision = revision });

    private static Task<ClientOwnerTransferPreview> PreviewAsync(IServiceProvider services, OwnerTransferActor actor, PathScope scope, long id) =>
        scope == PathScope.Single ? services.GetRequiredService<ClientOwnerTransferService>().PreviewClientAsync(actor.Context, id.ToString(), CancellationToken.None)
            : services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(actor.Context, id.ToString(), CancellationToken.None);

    internal static async Task SeedAsync(SpecusDbContext db, string tenant)
    {
        var now = DateTimeOffset.UtcNow.AddDays(-1);
        db.ClientAccounts.AddRange(
            new ClientAccount { Id = 1001, TenantId = tenant, ClientName = "laptop", OwnerUsername = "alice", PasswordHash = "retained-password", Enabled = true, CreatedAt = now, UpdatedAt = now },
            new ClientAccount { Id = 1002, TenantId = tenant, ClientName = "offline", OwnerUsername = "carol", PasswordHash = "retained-password", Enabled = false, CreatedAt = now, UpdatedAt = now });
        db.ClientCredentials.Add(new ClientCredential { Id = 501, TenantId = tenant, OwnerUsername = "alice", ApiKey = "retained-api", SecretHash = "retained-secret", Enabled = false, CreatedAt = now, UpdatedAt = now });
        db.ClientIdentities.AddRange(
            new ClientIdentity { Id = 701, TenantId = tenant, CredentialId = 501, ClientId = 1001, ClientName = "laptop", MachineFingerprint = "retained-machine1", OsUser = "retained-user", FirstSeenAt = now, LastSeenAt = now },
            new ClientIdentity { Id = 702, TenantId = tenant, CredentialId = 501, ClientId = 1002, ClientName = "offline", MachineFingerprint = "retained-machine2", OsUser = "retained-user", FirstSeenAt = now, LastSeenAt = now });
        db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 801, TenantId = tenant, ClientId = 1001, ClientName = "laptop", OwnerUsername = "alice", Enabled = true, VirtualIp = "10.66.0.3", Cidr = "10.66.0.0/16", PublicKey = "retained-public-key", CreatedAt = now, UpdatedAt = now });
        db.ClientSessions.Add(new ClientSession { Id = 901, TenantId = tenant, CredentialId = 501, IdentityId = 701, ClientId = 1001, ClientName = "laptop", TokenHash = "retained-token-hash", Status = "NETTY_ONLINE", ChannelId = "retained-control", MachineFingerprint = "retained-machine1", OsUser = "retained-user", HttpLoginAt = now, ExpiresAt = now.AddDays(2) });
        db.ManagementUsers.Add(new ManagementUser { Username = "bob-key", LoginName = "bob", TenantId = tenant, Enabled = true });
        await db.SaveChangesAsync();
    }

    internal static async Task VerifyAsync(TestServerFixture server)
    {
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var actor = await ActorAsync(server, services.ServiceProvider);
        await SeedAsync(db, actor.Context.TenantId);
        var before = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501);
        var session = JsonSerializer.Serialize(await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == 901));
        var identities = JsonSerializer.Serialize(await db.ClientIdentities.AsNoTracking().OrderBy(i => i.Id).ToListAsync());
        var preview = await OwnerTransferWriterProof.PreviewAsync(services.ServiceProvider, actor, PathScope.CredentialGroup, 501);
        var writer = services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>();
        var outcome = await writer.CommitAsync(actor, PathScope.CredentialGroup, "501", OwnerTransferWriterProof.Body(PathScope.CredentialGroup, " BoB ", preview.Revision!), CancellationToken.None);
        Assert.True(outcome.Response.Changed); Assert.True(outcome.Response.AccessRetained); Assert.NotNull(outcome.AuditId);
        Assert.Equal(new long[] { 1001, 1002 }, outcome.Response.AffectedClientIds);
        var after = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501);
        Assert.Equal("bob", after.OwnerUsername); Assert.Equal(before.SecretHash, after.SecretHash); Assert.Equal(before.ApiKey, after.ApiKey); Assert.Equal(before.Enabled, after.Enabled);
        var accounts = await db.ClientAccounts.AsNoTracking().Where(c => c.Id == 1001 || c.Id == 1002).OrderBy(c => c.Id).ToListAsync();
        Assert.All(accounts, c => Assert.Equal("bob", c.OwnerUsername)); Assert.True(accounts[0].Enabled); Assert.False(accounts[1].Enabled);
        var peer = await db.PeerMeshDevices.AsNoTracking().SingleAsync(p => p.Id == 801);
        Assert.Equal("bob", peer.OwnerUsername); Assert.Equal("retained-public-key", peer.PublicKey);
        Assert.Equal(identities, JsonSerializer.Serialize(await db.ClientIdentities.AsNoTracking().OrderBy(i => i.Id).ToListAsync()));
        Assert.Equal(session, JsonSerializer.Serialize(await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == 901)));
        var audit = await db.ClientOwnerTransferAudits.AsNoTracking().SingleAsync();
        Assert.Equal(actor.Context.Username, audit.Actor); Assert.Equal("bob", audit.TargetUsername);
        Assert.Contains("alice", audit.DetailJson); Assert.Contains("carol", audit.DetailJson);
        Assert.DoesNotContain("retained-", audit.DetailJson);
        var fresh = await OwnerTransferWriterProof.PreviewAsync(services.ServiceProvider, actor, PathScope.CredentialGroup, 501);
        var noOp = await writer.CommitAsync(actor, PathScope.CredentialGroup, "501", OwnerTransferWriterProof.Body(PathScope.CredentialGroup, "bob", fresh.Revision!), CancellationToken.None);
        Assert.False(noOp.Response.Changed); Assert.Null(noOp.AuditId); Assert.Equal(1, await db.ClientOwnerTransferAudits.CountAsync());
        var preservedAudit = JsonSerializer.Serialize(await db.ClientOwnerTransferAudits.AsNoTracking().SingleAsync());
        var history = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        var previous = db.Database.GetMigrations().TakeWhile(m => !m.EndsWith("_AddClientOwnerTransferAudit", StringComparison.Ordinal)).Last();
        await Assert.ThrowsAsync<NotSupportedException>(() => db.GetService<IMigrator>().MigrateAsync(previous));
        Assert.Equal(history, await db.Database.GetAppliedMigrationsAsync());
        Assert.Equal(preservedAudit, JsonSerializer.Serialize(await db.ClientOwnerTransferAudits.AsNoTracking().SingleAsync()));
    }
}
