using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

// Same signed HTTP pipeline and real database lock graph on all three mandatory providers.
internal static class ClientStartupProviderProof
{
    private const string Api = "ck_native_startup", Secret = "native-startup-fixture-secret";

    internal static async Task VerifyTransferBeforeStartupAsync(TestServerFixture server, StartupGate gate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var ct = timeout.Token;
        await SeedAsync(server);
        using var client = server.CreateClient();
        var pending = client.PostAsJsonAsync("/api/client/auth/login", Signed(gate.Nonce, "CanonicalMachine", "CanonicalUser"), ct);
        try
        {
            await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            await using (var scope = server.HostServices.CreateAsyncScope())
            {
                var actor = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
                var preview = await scope.ServiceProvider.GetRequiredService<ClientOwnerTransferService>()
                    .PreviewCredentialAsync(actor.Context, "6301", ct);
                Assert.Empty(preview.AffectedClients);
                await scope.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor,
                    PathScope.CredentialGroup, "6301", Body(preview), ct);
            }
            gate.Release.TrySetResult(true);
            using var response = await pending;
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var login = await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(ct);
            Assert.NotNull(login);
            await VerifyOwnerAndPublicationAsync(server, login, "bob", ct);
            using var secondResponse = await client.PostAsJsonAsync("/api/client/auth/login",
                Signed(Guid.NewGuid().ToString("N"), "canonicalmachine", "canonicaluser"), ct);
            Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
            var second = await secondResponse.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(ct);
            Assert.NotNull(second);
            await VerifyOwnerAndPublicationAsync(server, second, "bob", ct);
            await using var verify = server.HostServices.CreateAsyncScope();
            var db = verify.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var row = await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == second.ClientSessionId, ct);
            var identity = await db.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == row.IdentityId, ct);
            var memory = verify.ServiceProvider.GetRequiredService<ClientAuthSessionStore>().Find(second.ClientSessionId, second.AccessToken);
            Assert.NotNull(memory);
            Assert.Equal(identity.MachineFingerprint, row.MachineFingerprint); Assert.Equal(identity.OsUser, row.OsUser);
            Assert.Equal(identity.MachineFingerprint, memory.MachineFingerprint); Assert.Equal(identity.OsUser, memory.OsUser);
            if (db.Database.ProviderName == "MySql.EntityFrameworkCore")
            {
                Assert.Equal(login.ClientId, second.ClientId);
                Assert.Equal("CanonicalMachine", row.MachineFingerprint); Assert.Equal("CanonicalUser", row.OsUser);
            }
        }
        finally
        {
            gate.Release.TrySetResult(true);
            if (!pending.IsCompleted) { timeout.Cancel(); try { using var ignored = await pending; } catch (Exception) { } }
        }
    }

    internal static async Task VerifyStartupBeforeTransferAsync(TestServerFixture server, StartupGate gate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var ct = timeout.Token;
        await SeedAsync(server);
        await using var transferScope = server.HostServices.CreateAsyncScope();
        await using var observerScope = server.HostServices.CreateAsyncScope();
        var services = transferScope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services);
        var preview = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(actor.Context, "6301", ct);
        Assert.Empty(preview.AffectedClients);
        await db.Database.OpenConnectionAsync(ct);
        var postgres = db.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";
        var transferPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(db, postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()", ct));
        var observer = observerScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await observer.Database.OpenConnectionAsync(ct);
        var maria = Convert.ToString(await OwnerTransferWriterProof.ScalarAsync(observer, "SELECT VERSION()", ct))!.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        using var client = server.CreateClient();
        var pending = client.PostAsJsonAsync("/api/client/auth/login", Signed(gate.Nonce, "BlockingMachine", "BlockingUser"), ct);
        Task<OwnerTransferWriteOutcome>? transfer = null;
        try
        {
            await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.NotNull(gate.SessionId);
            Assert.Null(server.HostServices.GetRequiredService<ClientAuthSessionStore>().FindById(gate.SessionId));
            Assert.Equal(0, await observer.ClientAccounts.CountAsync(ct));
            Assert.Equal(0, await observer.ClientIdentities.CountAsync(ct));
            Assert.Equal(0, await observer.PeerMeshDevices.CountAsync(ct));
            transfer = services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor, PathScope.CredentialGroup, "6301", Body(preview), ct);
            await OwnerTransferWriterProof.WaitForBlockerAsync(observer, transferPid, gate.BackendId, postgres, maria, transfer, ct);
            gate.Release.TrySetResult(true);
            using var response = await pending;
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var login = await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(ct);
            Assert.NotNull(login);
            var changed = await Assert.ThrowsAsync<ClientOwnerTransferException>(() => transfer);
            Assert.Equal("TRANSFER_PREVIEW_CHANGED", changed.Code);
            Assert.Equal(0, await db.ClientOwnerTransferAudits.CountAsync(ct));
            await VerifyOwnerAndPublicationAsync(server, login, "alice", ct);
            var fresh = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(actor.Context, "6301", ct);
            Assert.Equal(login.ClientId, Assert.Single(fresh.AffectedClients).Id);
            var result = await services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor, PathScope.CredentialGroup, "6301", Body(fresh), ct);
            Assert.True(result.Response.Changed);
            await VerifyOwnerAndPublicationAsync(server, login, "bob", ct);
        }
        finally
        {
            gate.Release.TrySetResult(true);
            if (!pending.IsCompleted || transfer is { IsCompleted: false })
            {
                timeout.Cancel();
                try { using var ignored = await pending; } catch (Exception) { }
                if (transfer is not null) try { await transfer; } catch (Exception) { }
            }
        }
    }

    private static async Task VerifyOwnerAndPublicationAsync(TestServerFixture server, ClientAuthLoginResponse login, string owner, CancellationToken ct)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == login.ClientId, ct);
        var peer = await db.PeerMeshDevices.AsNoTracking().SingleAsync(p => p.ClientId == login.ClientId, ct);
        var credential = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 6301, ct);
        Assert.Equal(owner, account.OwnerUsername); Assert.Equal(owner, peer.OwnerUsername); Assert.Equal(owner, credential.OwnerUsername);
        Assert.False(peer.Enabled); Assert.True(credential.Enabled); Assert.Equal(Hash(Secret), credential.SecretHash);
        Assert.Equal(7, login.MaxOnlineInstances);
        var row = await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == login.ClientSessionId, ct);
        Assert.Equal(account.Id, row.ClientId); Assert.Equal(credential.Id, row.CredentialId);
        Assert.Equal(Hash(login.AccessToken), row.TokenHash);
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ClientAuthSessionStore>().Find(login.ClientSessionId, login.AccessToken));
    }

    private static JsonElement Body(ClientOwnerTransferPreview preview) => JsonSerializer.SerializeToElement(new
    { scope = "credential-group", targetUsername = "bob", expectedRevision = preview.Revision });

    private static async Task SeedAsync(TestServerFixture server)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var tenant = scope.ServiceProvider.GetRequiredService<IOptions<AuthOptions>>().Value.TenantId;
        Assert.Equal("default", tenant);
        var now = DateTimeOffset.UtcNow;
        db.ClientCredentials.Add(new ClientCredential { Id = 6301, TenantId = tenant, OwnerUsername = "alice", ApiKey = Api, SecretHash = Hash(Secret), Enabled = true, MaxOnlineInstances = 7, CreatedAt = now, UpdatedAt = now });
        db.ManagementUsers.Add(new ManagementUser { Username = "native-startup-bob", LoginName = "bob", TenantId = tenant, Enabled = true });
        await db.SaveChangesAsync();
    }

    private static ClientAuthLoginRequest Signed(string nonce, string machine, string user)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        return new ClientAuthLoginRequest { ApiKey = Api, Timestamp = timestamp, Nonce = nonce,
            Signature = Convert.ToHexStringLower(HMACSHA256.HashData(SHA256.HashData(Encoding.UTF8.GetBytes(Secret)), Encoding.UTF8.GetBytes(string.Join('\n', Api, timestamp, nonce, machine, user)))),
            Environment = new ClientEnvironmentInfo { MachineFingerprint = machine, OsUser = user, Hostname = "native-startup", PeerPublicKey = "native-startup-public-key" } };
    }
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    internal sealed class StartupGate(bool beforeSession) : SaveChangesInterceptor
    {
        private int entered;
        internal string Nonce { get; } = Guid.NewGuid().ToString("N");
        internal long BackendId { get; private set; }
        internal long? SessionId { get; private set; }
        internal TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (!beforeSession && eventData.Context is SpecusDbContext db
                && db.ChangeTracker.Entries<ClientAuthNonce>().Any(e => e.Entity.ApiKeyHash == Hash(Api) && e.Entity.NonceHash == Hash(Nonce)))
                await CaptureAsync(db, cancellationToken);
            return result;
        }
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (beforeSession && eventData.Context is SpecusDbContext db)
            {
                var session = db.ChangeTracker.Entries<ClientSession>().SingleOrDefault(e => e.State == EntityState.Added && e.Entity.CredentialId == 6301)?.Entity;
                if (session is not null) { SessionId = session.Id; await CaptureAsync(db, cancellationToken); }
            }
            return result;
        }
        private async Task CaptureAsync(SpecusDbContext db, CancellationToken ct)
        {
            if (Interlocked.CompareExchange(ref entered, 1, 0) != 0) return;
            // Pin this real request's connection so the native observer can identify its backend.
            // The request's scoped DbContext disposes it; no authentication or policy is bypassed.
            await db.Database.OpenConnectionAsync(ct);
            BackendId = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(db,
                db.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL" ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()", ct));
            Entered.TrySetResult(true);
            await Release.Task.WaitAsync(ct);
        }
    }
}
