using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.IntegrationTests;

// Control/NAT fixture issuer, not a bypass in production authentication. Persist the same
// immutable identity/session authority as startup before publishing its token in memory.
internal static class TestClientSession
{
    internal static async Task<ClientAuthSession> CreateAsync(TestServerFixture server, ClientCredential credential,
        ClientIdentity identity, ClientAccount account, TimeSpan ttl, ClientEnvironmentInfo environment)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var current = await db.ClientIdentities.AsNoTracking().SingleOrDefaultAsync(i => i.CredentialId == credential.Id
            && i.MachineFingerprint == identity.MachineFingerprint && i.OsUser == identity.OsUser);
        if (current is not null)
        {
            if (current.ClientId != account.Id || current.TenantId != account.TenantId)
                throw new InvalidOperationException("fixture machine/user identity belongs to another account");
            identity = current;
        }
        else db.ClientIdentities.Add(identity);
        var store = scope.ServiceProvider.GetRequiredService<ClientAuthSessionStore>();
        var session = store.Prepare(credential, identity, account, ttl, environment);
        db.ClientSessions.Add(ClientAccountService.ToSessionEntity(session, environment));
        await db.SaveChangesAsync();
        store.Publish(session);
        return session;
    }
}
