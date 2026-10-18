using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Persistence;

namespace Specus.IntegrationTests;

public sealed class ClientSessionRevocationTests
{
    [Fact]
    public void CommittedClientRevocationRejectsLatePublicationAndOnlinePromotion()
    {
        var store = new ClientAuthSessionStore();
        var credential = new ClientCredential { Id = 501, TenantId = "default" };
        var identity = new ClientIdentity { Id = 701 };
        var client = new ClientAccount { Id = 1001 };
        var online = store.Create(credential, identity, client, TimeSpan.FromHours(1), new ClientEnvironmentInfo());
        var prepared = store.Prepare(credential, identity, client, TimeSpan.FromHours(1), new ClientEnvironmentInfo());
        Assert.True(store.MarkOnline(online, "before", null));
        store.RevokeClient("default", 1001);
        Assert.Throws<ArgumentException>(() => store.Publish(prepared));
        Assert.False(store.MarkOnline(online, "too-late", null));
        Assert.Null(store.Find(online.Id, online.AccessToken));
        Assert.NotNull(store.FindById(online.Id));
        Assert.Null(store.FindById(prepared.Id));
        Assert.Equal(0, store.CountOnlineByCredential(501));
    }

    [Fact]
    public void RevocationUsesExactTenantAndClientIdNotSharedCredentialOrDisplayName()
    {
        var store = new ClientAuthSessionStore();
        ClientAuthSession Create(string tenant, long client) => store.Create(new ClientCredential { Id = 501, TenantId = tenant },
            new ClientIdentity { Id = client }, new ClientAccount { Id = client, ClientName = "same-name" }, TimeSpan.FromHours(1), new ClientEnvironmentInfo());
        var deleted = Create("default", 1001); var sibling = Create("default", 1002); var foreign = Create("DEFAULT", 1001);
        foreach (var session in new[] { deleted, sibling, foreign }) Assert.True(store.MarkOnline(session, "fixture", null));
        store.RevokeClient("default", 1001);
        Assert.Null(store.Find(deleted.Id, deleted.AccessToken));
        Assert.NotNull(store.Find(sibling.Id, sibling.AccessToken));
        Assert.NotNull(store.Find(foreign.Id, foreign.AccessToken));
        Assert.Equal(2, store.CountOnlineByCredential(501));
    }

    [Fact]
    public void ExpiredCachedOnlineSessionsDoNotOccupyOnlineQuota()
    {
        var store = new ClientAuthSessionStore();
        var expired = store.Create(new ClientCredential { Id = 501 }, new ClientIdentity { Id = 701 }, new ClientAccount { Id = 1001 },
            TimeSpan.FromSeconds(-1), new ClientEnvironmentInfo { MachineFingerprint = "machine", OsUser = "user" });
        Assert.False(store.MarkOnline(expired, "expired", null));
        Assert.Equal(0, store.CountOnlineByCredential(501));
        Assert.Equal(0, store.CountOnlineByMachineUser(501, "machine", "user"));
    }

    [Fact]
    public async Task FailedDeletionCommitDoesNotRevokePublishedTokenOrExpireSqlHistory()
    {
        var fault = new CommitFault();
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        { ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true", ["Specus:PeerMesh:StunTurnPort"] = "0", ["Specus:PeerMesh:NatProbeAlternatePort"] = "0" },
            services => services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(fault)));
        var login = await ClientSessionAuthorityTests.LoginAsync(server);
        var store = server.HostServices.GetRequiredService<ClientAuthSessionStore>();
        var cached = store.Find(login.ClientSessionId, login.AccessToken); Assert.NotNull(cached);
        store.MarkOnline(cached, "must-survive", null);
        await using var scope = server.HostServices.CreateAsyncScope();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
        fault.Armed = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => scope.ServiceProvider.GetRequiredService<ManagementMutationService>()
            .DeleteClientAsync(actor.Context, login.ClientId, CancellationToken.None));
        Assert.True(fault.Triggered); Assert.NotNull(store.Find(login.ClientSessionId, login.AccessToken));
        Assert.Equal(1, store.CountOnlineByCredential(501));
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.Equal(cached.ExpiresAt, (await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == login.ClientSessionId)).ExpiresAt);
        Assert.True(await db.ClientIdentities.AsNoTracking().AnyAsync(i => i.Id == 701));
    }

    [Fact]
    public async Task SqlOnlineMachineQuotaIncludesAnotherHostsUncachedSession()
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        var login = await ClientSessionAuthorityTests.LoginAsync(server);
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var remote = await db.ClientSessions.SingleAsync(s => s.Id == 901);
        remote.Status = ClientAccountService.StatusNettyOnline; remote.ExpiresAt = DateTimeOffset.UtcNow.AddHours(1);
        await db.SaveChangesAsync();
        Assert.Null(server.HostServices.GetRequiredService<ClientAuthSessionStore>().FindById(901));
        var result = await scope.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(
            new Specus.Protocol.Packets.LoginRequestPacket { ClientSessionId = login.ClientSessionId, AccessToken = login.AccessToken },
            "must-not-exceed-remote-machine-quota", null, CancellationToken.None);
        Assert.False(result.Success); Assert.Equal("同一台机器和用户已经有在线实例", result.Reason);
    }

    [Theory]
    [InlineData("2000-01-01T00:00:00Z")]
    [InlineData("2000-01-01T00:00:00.123Z")]
    [InlineData("2000-01-01T00:00:00.1234567Z")]
    public async Task DeletionPreservesExpiredHistoryWithLegacyIsoPrecisionByteForByte(string legacy)
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        var login = await ClientSessionAuthorityTests.LoginAsync(server);
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await db.Database.OpenConnectionAsync();
        var (table, key) = ClientOwnershipWrite.Identifiers<ClientSession>(db, "Id");
        var expires = ClientOwnershipWrite.Identifiers<ClientSession>(db, "ExpiresAt").Key;
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = $"UPDATE {table} SET {expires}=@expiry WHERE {key}=@id";
        var value = command.CreateParameter(); value.ParameterName = "@expiry"; value.Value = legacy; command.Parameters.Add(value);
        var id = command.CreateParameter(); id.ParameterName = "@id"; id.Value = 901L; command.Parameters.Add(id);
        Assert.Equal(1, await command.ExecuteNonQueryAsync());
        var actor = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
        await scope.ServiceProvider.GetRequiredService<ManagementMutationService>().DeleteClientAsync(actor.Context, login.ClientId, CancellationToken.None);
        command.Parameters.Remove(value);
        command.CommandText = $"SELECT {expires} FROM {table} WHERE {key}=@id";
        Assert.Equal(legacy, Convert.ToString(await command.ExecuteScalarAsync()));
        Assert.Null(server.HostServices.GetRequiredService<ClientAuthSessionStore>().Find(login.ClientSessionId, login.AccessToken));
    }

    private sealed class CommitFault : DbTransactionInterceptor
    {
        internal bool Armed { get; set; }
        internal bool Triggered { get; private set; }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData eventData,
            InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (Armed) { Triggered = true; throw new InvalidOperationException("owned deletion revocation commit fixture failure"); }
            return ValueTask.FromResult(result);
        }
    }
}
