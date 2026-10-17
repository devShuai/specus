using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.IntegrationTests;

public sealed class ClientStartupAtomicityTests
{
    private const string Api = "ck_startup_atomic", Secret = "startup-atomic-secret";

    [Theory]
    [InlineData("disabled")]
    [InlineData("deleted")]
    [InlineData("secret")]
    [InlineData("api-key")]
    [InlineData("tenant")]
    public async Task SignedCredentialInvalidatedAfterSignatureCannotProvisionOrIssueASession(string mutation)
    {
        var nonce = Guid.NewGuid().ToString("N");
        var barrier = new ClientStartupOwnershipTests.NonceSavedBarrier(ClientStartupOwnershipTests.Hash(Api), ClientStartupOwnershipTests.Hash(nonce));
        await using var server = await StartAsync(barrier);
        await SeedAsync(server);
        using var client = server.CreateClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var pending = client.PostAsJsonAsync("/api/client/auth/login", ClientStartupOwnershipTests.Signed(Api, Secret, nonce), timeout.Token);
        try
        {
            await barrier.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await using (var scope = server.HostServices.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
                var credential = await db.ClientCredentials.SingleAsync(c => c.Id == 6201, timeout.Token);
                if (mutation == "disabled") credential.Enabled = false;
                else if (mutation == "deleted") db.ClientCredentials.Remove(credential);
                else if (mutation == "secret") credential.SecretHash = ClientStartupOwnershipTests.Hash("rotated-secret");
                else if (mutation == "api-key") credential.ApiKey = "ck_replaced_api";
                else credential.TenantId = "other-tenant";
                await db.SaveChangesAsync(timeout.Token);
            }
            barrier.Release.TrySetResult(true);
            using var response = await pending;
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            await AssertNoStartupRowsAsync(server);
        }
        finally
        {
            barrier.Release.TrySetResult(true);
            if (!pending.IsCompleted) { timeout.Cancel(); try { using var ignored = await pending; } catch (Exception) { } }
        }
    }

    [Theory]
    [InlineData("configuration")]
    [InlineData("session-save")]
    [InlineData("session-deleted")]
    public async Task LateStartupFailureRollsBackSqlAndNeverPublishesItsPreparedToken(string fault)
    {
        var gate = new SessionSaveProbe(fault == "session-save");
        await using var server = await StartAsync(gate, fault == "configuration");
        await SeedAsync(server);
        if (fault == "session-deleted")
        {
            await using var scope = server.HostServices.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<SpecusDbContext>().Database.ExecuteSqlRawAsync(
                "CREATE TRIGGER startup_session_fault AFTER INSERT ON specus_client_session BEGIN DELETE FROM specus_client_session WHERE Id=NEW.Id; END");
        }
        using var client = server.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/client/auth/login", ClientStartupOwnershipTests.Signed(Api, Secret, Guid.NewGuid().ToString("N")));
        Assert.Equal(fault == "configuration" ? HttpStatusCode.BadRequest : HttpStatusCode.Conflict, response.StatusCode);
        if (gate.SessionId is { } id)
            Assert.Null(server.HostServices.GetRequiredService<ClientAuthSessionStore>().FindById(id));
        if (fault != "configuration") Assert.NotNull(gate.SessionId);
        await AssertNoStartupRowsAsync(server);
    }

    [Fact]
    public async Task ExistingClientKeepsItsOwnCurrentOwnerAndKeyRatherThanCredentialOwner()
    {
        await using var server = await StartAsync();
        await SeedAsync(server);
        var now = DateTimeOffset.UtcNow;
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            db.ClientAccounts.Add(new ClientAccount { Id = 6202, TenantId = "default", OwnerUsername = "independent-owner", ClientName = "existing-startup", Enabled = true, PasswordHash = "retained-client-key", CreatedAt = now, UpdatedAt = now });
            db.ClientIdentities.Add(new ClientIdentity { Id = 6203, TenantId = "default", CredentialId = 6201, ClientId = 6202, ClientName = "existing-startup", MachineFingerprint = "startup-machine", OsUser = "startup-user", FirstSeenAt = now, LastSeenAt = now });
            await db.SaveChangesAsync();
        }
        using var client = server.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/client/auth/login", ClientStartupOwnershipTests.Signed(Api, Secret, Guid.NewGuid().ToString("N")));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var login = await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>();
        Assert.NotNull(login); Assert.Equal(6202, login.ClientId);
        await using var verify = server.HostServices.CreateAsyncScope();
        var database = verify.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await database.ClientAccounts.AsNoTracking().SingleAsync();
        Assert.Equal("independent-owner", account.OwnerUsername); Assert.Equal("retained-client-key", account.PasswordHash);
        Assert.Equal("independent-owner", (await database.PeerMeshDevices.AsNoTracking().SingleAsync()).OwnerUsername);
        Assert.Equal("alice", (await database.ClientCredentials.AsNoTracking().SingleAsync()).OwnerUsername);
    }

    [Theory]
    [InlineData("disabled-client")]
    [InlineData("foreign-identity")]
    [InlineData("missing-client")]
    public async Task InconsistentOrDisabledExistingBindingFailsWithoutProvisioningAnotherDevice(string fault)
    {
        await using var server = await StartAsync();
        await SeedAsync(server);
        var now = DateTimeOffset.UtcNow;
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            if (fault != "missing-client") db.ClientAccounts.Add(new ClientAccount { Id = 6202, TenantId = "default", OwnerUsername = "alice", ClientName = "existing-startup", Enabled = fault != "disabled-client", PasswordHash = "retained-client-key", CreatedAt = now, UpdatedAt = now });
            db.ClientIdentities.Add(new ClientIdentity { Id = 6203, TenantId = fault == "foreign-identity" ? "foreign" : "default", CredentialId = 6201, ClientId = 6202, ClientName = "existing-startup", MachineFingerprint = "startup-machine", OsUser = "startup-user", FirstSeenAt = now, LastSeenAt = now });
            await db.SaveChangesAsync();
        }
        using var client = server.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/client/auth/login", ClientStartupOwnershipTests.Signed(Api, Secret, Guid.NewGuid().ToString("N")));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await using var verify = server.HostServices.CreateAsyncScope();
        var database = verify.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.Equal(fault == "missing-client" ? 0 : 1, await database.ClientAccounts.CountAsync());
        Assert.Equal(1, await database.ClientIdentities.CountAsync());
        Assert.Equal(0, await database.ClientSessions.CountAsync()); Assert.Equal(0, await database.PeerMeshDevices.CountAsync());
    }

    internal static Task<TestServerFixture> StartAsync(IInterceptor? interceptor = null, bool badConfiguration = false) =>
        TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true",
            ["Specus:PeerMesh:Cidr"] = badConfiguration ? "not-a-cidr" : "10.66.0.0/16",
            ["Specus:PeerMesh:StunTurnPort"] = "0", ["Specus:PeerMesh:NatProbeAlternatePort"] = "0",
        }, services => { if (interceptor is not null) services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(interceptor)); });

    internal static async Task SeedAsync(TestServerFixture server)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>(); var now = DateTimeOffset.UtcNow;
        db.ClientCredentials.Add(new ClientCredential { Id = 6201, TenantId = "default", OwnerUsername = "alice", ApiKey = Api, SecretHash = ClientStartupOwnershipTests.Hash(Secret), Enabled = true, MaxOnlineInstances = 7, CreatedAt = now, UpdatedAt = now });
        await db.SaveChangesAsync();
    }

    private static async Task AssertNoStartupRowsAsync(TestServerFixture server)
    {
        await using var scope = server.HostServices.CreateAsyncScope(); var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.Equal(0, await db.ClientAccounts.CountAsync()); Assert.Equal(0, await db.ClientIdentities.CountAsync());
        Assert.Equal(0, await db.ClientSessions.CountAsync()); Assert.Equal(0, await db.PeerMeshDevices.CountAsync());
    }

    internal sealed class SessionSaveProbe(bool fail) : SaveChangesInterceptor
    {
        internal long? SessionId { get; private set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            var session = eventData.Context?.ChangeTracker.Entries<ClientSession>().SingleOrDefault(e => e.State == EntityState.Added)?.Entity;
            if (session is not null)
            {
                SessionId = session.Id;
                if (fail) throw new InvalidOperationException("owned startup session-save fixture failure");
            }
            return ValueTask.FromResult(result);
        }
    }
}
