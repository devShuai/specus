using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class ClientSessionAuthorityTests
{
    [Theory]
    [InlineData("missing-session")]
    [InlineData("expired-session")]
    [InlineData("token-hash")]
    [InlineData("session-client")]
    [InlineData("session-credential")]
    [InlineData("session-identity")]
    [InlineData("session-tenant")]
    [InlineData("session-machine")]
    [InlineData("session-user")]
    [InlineData("missing-identity")]
    [InlineData("identity-client")]
    [InlineData("identity-credential")]
    [InlineData("identity-tenant")]
    [InlineData("identity-machine")]
    [InlineData("identity-user")]
    [InlineData("disabled-client")]
    [InlineData("disabled-credential")]
    [InlineData("recreated-client")]
    public async Task CachedTokenCannotAuthenticateAgainstChangedCurrentSqlAuthority(string mutation)
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        var login = await LoginAsync(server);
        await using var warm = server.HostServices.CreateAsyncScope();
        var warmDb = warm.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await warmDb.ClientAccounts.SingleAsync(c => c.Id == login.ClientId);
        await warmDb.ClientCredentials.SingleAsync(c => c.Id == 501);
        await warmDb.ClientSessions.SingleAsync(c => c.Id == login.ClientSessionId);
        await warmDb.ClientIdentities.SingleAsync(c => c.Id == 701);
        await using (var change = server.HostServices.CreateAsyncScope())
        {
            var db = change.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var session = await db.ClientSessions.SingleAsync(s => s.Id == login.ClientSessionId);
            var identity = await db.ClientIdentities.SingleAsync(i => i.Id == 701);
            switch (mutation)
            {
                case "missing-session": db.ClientSessions.Remove(session); break;
                case "expired-session": session.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1); break;
                case "token-hash": session.TokenHash = "changed-hash"; break;
                case "session-client": session.ClientId = 1002; break;
                case "session-credential": session.CredentialId = 502; break;
                case "session-identity": session.IdentityId = 702; break;
                case "session-tenant": session.TenantId = "DEFAULT"; break;
                case "session-machine": session.MachineFingerprint = "changed-machine"; break;
                case "session-user": session.OsUser = "changed-user"; break;
                case "missing-identity": db.ClientIdentities.Remove(identity); break;
                case "identity-client": identity.ClientId = 1002; break;
                case "identity-credential": identity.CredentialId = 502; break;
                case "identity-tenant": identity.TenantId = "DEFAULT"; break;
                case "identity-machine": identity.MachineFingerprint = "changed-machine"; break;
                case "identity-user": identity.OsUser = "changed-user"; break;
                case "disabled-client": (await db.ClientAccounts.SingleAsync(c => c.Id == login.ClientId)).Enabled = false; break;
                case "disabled-credential": (await db.ClientCredentials.SingleAsync(c => c.Id == 501)).Enabled = false; break;
                case "recreated-client":
                    db.ClientIdentities.Remove(identity);
                    var old = await db.ClientAccounts.SingleAsync(c => c.Id == login.ClientId);
                    db.ClientAccounts.Remove(old); await db.SaveChangesAsync(); db.ChangeTracker.Clear();
                    db.ClientAccounts.Add(new ClientAccount { Id = login.ClientId, TenantId = "default", ClientName = "replacement", Enabled = true });
                    break;
            }
            await db.SaveChangesAsync();
        }
        var result = await warm.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(
            Packet(login), "authority-negative", "127.0.0.1", CancellationToken.None);
        Assert.False(result.Success);
    }

    [Fact]
    public async Task DataConnectionRequiresCurrentSqlControlStateNotOnlyCachedOnlineState()
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        var login = await LoginAsync(server);
        await using (var online = server.HostServices.CreateAsyncScope())
            Assert.True((await online.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(Packet(login), "online-before", "127.0.0.1", CancellationToken.None)).Success);
        await using (var offline = server.HostServices.CreateAsyncScope())
        {
            var db = offline.ServiceProvider.GetRequiredService<SpecusDbContext>();
            (await db.ClientSessions.SingleAsync(s => s.Id == login.ClientSessionId)).Status = ClientAccountService.StatusDisconnected;
            await db.SaveChangesAsync();
        }
        await using var scope = server.HostServices.CreateAsyncScope();
        Assert.False((await scope.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateDataAsync(
            Packet(login), "cached-data", "127.0.0.1", CancellationToken.None)).Success);
    }

    [Fact]
    public async Task DeletionRevokesCachedTokenAndOnlineQuotaButRetainsAuditMetadata()
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        var login = await LoginAsync(server);
        var store = server.HostServices.GetRequiredService<ClientAuthSessionStore>();
        var cached = store.Find(login.ClientSessionId, login.AccessToken); Assert.NotNull(cached);
        store.MarkOnline(cached, "not-yet-registered-channel", "127.0.0.1");
        Assert.Equal(1, store.CountOnlineByCredential(501));
        await using (var deletion = server.HostServices.CreateAsyncScope())
        {
            var actor = await OwnerTransferWriterProof.ActorAsync(server, deletion.ServiceProvider);
            await deletion.ServiceProvider.GetRequiredService<ManagementMutationService>().DeleteClientAsync(actor.Context, login.ClientId, CancellationToken.None);
        }
        Assert.Null(store.Find(login.ClientSessionId, login.AccessToken));
        Assert.Equal(0, store.CountOnlineByCredential(501));
        Assert.Equal(0, store.CountOnlineByMachineUser(501, cached.MachineFingerprint, cached.OsUser));
        Assert.NotNull(store.FindById(login.ClientSessionId));
        await using var scope = server.HostServices.CreateAsyncScope();
        var historical = await scope.ServiceProvider.GetRequiredService<SpecusDbContext>().ClientSessions.AsNoTracking().SingleAsync(s => s.Id == login.ClientSessionId);
        Assert.Equal(login.ClientId, historical.ClientId); Assert.Equal(login.ClientName, historical.ClientName);
        Assert.True(historical.ExpiresAt <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task ValidSqlSessionCanReconnectAfterRenameAndIgnoresSuppliedDisplayName()
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        var login = await LoginAsync(server);
        await using (var rename = server.HostServices.CreateAsyncScope())
        {
            var actor = await OwnerTransferWriterProof.ActorAsync(server, rename.ServiceProvider);
            await rename.ServiceProvider.GetRequiredService<ManagementMutationService>().UpdateClientAsync(actor.Context, login.ClientId,
                new ClientMutation("canonical-session-name", null, null), CancellationToken.None);
        }
        await using var scope = server.HostServices.CreateAsyncScope();
        var packet = Packet(login); packet.ClientName = "untrusted-name";
        var result = await scope.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(packet, "canonical-reconnect", "127.0.0.1", CancellationToken.None);
        Assert.True(result.Success); Assert.Equal("canonical-session-name", packet.ClientName);
    }

    private static LoginRequestPacket Packet(ClientAuthLoginResponse login) => new()
    { ClientSessionId = login.ClientSessionId, AccessToken = login.AccessToken, ClientName = login.ClientName };

    internal static async Task<ClientAuthLoginResponse> LoginAsync(TestServerFixture server)
    {
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
            await ClientNameReferenceTests.SeedAsync(db); await ClientNameReferenceTests.EnableCredentialAsync(db);
        }
        using var http = server.CreateClient();
        using var response = await http.PostAsJsonAsync("/api/client/auth/login", ClientNameReferenceTests.Request());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>())!;
    }
}
