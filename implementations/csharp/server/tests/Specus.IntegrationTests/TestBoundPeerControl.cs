using Microsoft.EntityFrameworkCore;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.IntegrationTests;

// Fixture-only publisher for a control already accepted by the test harness. It is not
// a production auth bypass or a substitute for the signed HTTP/network acceptance tests.
internal static class TestBoundPeerControl
{
    internal static async Task PublishAsync(SpecusDbContext db, ClientAuthSessionStore store, ClientAccount account,
        SpecusConnectionContext context, long? sessionId = null)
    {
        var row = sessionId is not null
            ? await db.ClientSessions.SingleOrDefaultAsync(s => s.Id == sessionId)
            : await db.ClientSessions.Where(s => s.ClientId == account.Id && s.TenantId == account.TenantId)
                .OrderByDescending(s => s.Id).FirstOrDefaultAsync();
        if (row is not null && (row.ClientId != account.Id || row.TenantId != account.TenantId))
            throw new InvalidOperationException("fixture session belongs to another account/tenant");
        var identity = row?.IdentityId > 0 ? await db.ClientIdentities.SingleOrDefaultAsync(i => i.Id == row.IdentityId)
            : await db.ClientIdentities.FirstOrDefaultAsync(i => i.ClientId == account.Id && i.TenantId == account.TenantId);
        var credentialId = row?.CredentialId > 0 ? row.CredentialId : identity?.CredentialId ?? ClientIdGenerator.NewId();
        var credential = await db.ClientCredentials.SingleOrDefaultAsync(c => c.Id == credentialId);
        if (credential is null)
        {
            credential = new ClientCredential { Id = credentialId, TenantId = account.TenantId, OwnerUsername = account.OwnerUsername,
                ApiKey = "bound-fixture-" + credentialId, SecretHash = ClientStartupOwnershipTests.Hash("bound-fixture-secret"), Enabled = true };
            db.ClientCredentials.Add(credential);
        }
        if (credential.TenantId != account.TenantId) throw new InvalidOperationException("fixture credential tenant mismatch");
        credential.Enabled = true;
        if (identity is null)
        {
            identity = new ClientIdentity { Id = row?.IdentityId > 0 ? row.IdentityId : ClientIdGenerator.NewId(), TenantId = account.TenantId,
                ClientId = account.Id, CredentialId = credential.Id, ClientName = account.ClientName,
                MachineFingerprint = string.IsNullOrEmpty(row?.MachineFingerprint) ? "bound-fixture-" + account.Id : row.MachineFingerprint,
                OsUser = string.IsNullOrEmpty(row?.OsUser) ? "bound-fixture" : row.OsUser };
            db.ClientIdentities.Add(identity);
        }
        if (identity.ClientId != account.Id || identity.CredentialId != credential.Id || identity.TenantId != account.TenantId)
            throw new InvalidOperationException("fixture identity binding mismatch");
        row ??= new ClientSession { Id = sessionId ?? ClientIdGenerator.NewId(), TenantId = account.TenantId, ClientId = account.Id, ClientName = account.ClientName };
        if (db.Entry(row).State == EntityState.Detached) db.ClientSessions.Add(row);
        var binding = store.FindById(row.Id);
        if (binding is null)
        {
            var prepared = store.Prepare(credential, identity, account, TimeSpan.FromHours(1), new ClientEnvironmentInfo
            { MachineFingerprint = identity.MachineFingerprint, OsUser = identity.OsUser, Hostname = "bound-fixture" });
            binding = new ClientAuthSession { Id = row.Id, TenantId = account.TenantId, ClientId = account.Id, ClientName = account.ClientName,
                CredentialId = credential.Id, IdentityId = identity.Id, AccessToken = prepared.AccessToken, TokenHash = prepared.TokenHash,
                ExpiresAt = prepared.ExpiresAt, MachineFingerprint = identity.MachineFingerprint, OsUser = identity.OsUser, Hostname = prepared.Hostname };
        }
        row.CredentialId = credential.Id; row.IdentityId = identity.Id; row.TokenHash = binding.TokenHash;
        row.MachineFingerprint = binding.MachineFingerprint; row.OsUser = binding.OsUser;
        row.Status = ClientAccountService.StatusNettyOnline; row.ChannelId = context.ChannelId;
        row.ExpiresAt = binding.ExpiresAt; row.NettyConnectedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();
        if (store.FindById(row.Id) is null) store.Publish(binding);
        Assert.True(store.MarkOnline(binding, context.ChannelId, context.RemoteAddress));
        context.OnLoginSuccess(account.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), row.Id, tenantId: account.TenantId, clientId: account.Id);
    }
}
