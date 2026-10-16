using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;
using Specus.Server.Data.Conversion;
using Specus.Server.Data.Entities;
using Specus.Server.Persistence;

namespace Specus.Server.Authentication;

public sealed partial class ClientAccountService
{
    // Caller owns the complete HTTP startup transaction, through Peer/config/session persistence.
    // Owner and online limits are current metadata, NOT immutable authentication material.
    private async Task<(ClientCredential Credential, ClientAccount Account, ClientIdentity Identity)> ResolveClientStartupOnAsync(
        ClientCredential expected, ClientEnvironmentInfo environment, CancellationToken ct)
    {
        if (expected.Id <= 0 || string.IsNullOrWhiteSpace(expected.TenantId)) throw StartupChanged();
        await ClientOwnershipWrite.LockAsync<ClientCredential>(_db, expected.Id, expected.TenantId, ct).ConfigureAwait(false);
        var credential = await _db.ClientCredentials.AsNoTracking().SingleOrDefaultAsync(c => c.Id == expected.Id && c.TenantId == expected.TenantId, ct).ConfigureAwait(false);
        if (credential is null || !credential.Enabled || credential.TenantId != expected.TenantId
            || credential.ApiKey != expected.ApiKey || !CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(credential.SecretHash), Encoding.UTF8.GetBytes(expected.SecretHash))) throw StartupChanged();

        var hint = await _db.ClientIdentities.AsNoTracking().SingleOrDefaultAsync(i => i.CredentialId == credential.Id
            && i.MachineFingerprint == environment.MachineFingerprint && i.OsUser == environment.OsUser, ct).ConfigureAwait(false);
        if (hint is not null)
        {
            if (hint.Id <= 0 || hint.ClientId <= 0 || hint.TenantId != credential.TenantId) throw StartupChanged();
            await ClientOwnershipWrite.LockAsync<ClientAccount>(_db, hint.ClientId, credential.TenantId, ct).ConfigureAwait(false);
            await ClientOwnershipWrite.LockAsync<ClientIdentity>(_db, hint.Id, credential.TenantId, ct).ConfigureAwait(false);
            var account = await _db.ClientAccounts.AsNoTracking().SingleOrDefaultAsync(c => c.Id == hint.ClientId && c.TenantId == credential.TenantId, ct).ConfigureAwait(false);
            var identity = await _db.ClientIdentities.AsNoTracking().SingleOrDefaultAsync(i => i.Id == hint.Id, ct).ConfigureAwait(false);
            if (account is null || identity is null || account.TenantId != credential.TenantId || identity.TenantId != credential.TenantId
                || identity.CredentialId != credential.Id || identity.ClientId != account.Id || identity.ClientName != account.ClientName
                || identity.MachineFingerprint != hint.MachineFingerprint || identity.OsUser != hint.OsUser
                || string.IsNullOrWhiteSpace(identity.MachineFingerprint) || string.IsNullOrWhiteSpace(identity.OsUser)) throw StartupChanged();
            if (!account.Enabled) throw new ArgumentException("客户端已停用");
            identity.Hostname = Limit(environment.Hostname, 160); identity.LastSeenAt = DateTimeOffset.UtcNow;
            var (_, key) = ClientOwnershipWrite.Identifiers<ClientIdentity>(_db, "Id");
            await using var update = ClientOwnershipWrite.Command(_db,
                $"UPDATE specus_client_identity SET hostname=@host,last_seen_at=@seen WHERE {key}=@id AND tenant_id=@tenant",
                ("@host", identity.Hostname), ("@seen", IsoDateTimeOffsetConverter.Format(identity.LastSeenAt)), ("@id", identity.Id), ("@tenant", credential.TenantId));
            if (await update.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1) throw StartupChanged();
            return (credential, account, identity);
        }

        var now = DateTimeOffset.UtcNow;
        var created = new ClientAccount
        {
            Id = ClientIdGenerator.NewId(), TenantId = credential.TenantId, OwnerUsername = credential.OwnerUsername,
            ClientName = await GenerateClientNameAsync(credential, environment, ct).ConfigureAwait(false),
            PasswordHash = PasswordHasher.HashToken(Guid.NewGuid().ToString("N")), Enabled = true,
            ConnectionRateLimitPerMinute = 30, CreatedAt = now, UpdatedAt = now,
        };
        var binding = new ClientIdentity
        {
            Id = ClientIdGenerator.NewId(), TenantId = credential.TenantId, CredentialId = credential.Id,
            ClientId = created.Id, ClientName = created.ClientName, MachineFingerprint = environment.MachineFingerprint!,
            OsUser = environment.OsUser!, Hostname = Limit(environment.Hostname, 160), FirstSeenAt = now, LastSeenAt = now,
        };
        await ClientOwnershipWrite.InsertAsync(_db, created, ct).ConfigureAwait(false);
        await ClientOwnershipWrite.InsertAsync(_db, binding, ct).ConfigureAwait(false);
        var stored = await _db.ClientAccounts.AsNoTracking().SingleOrDefaultAsync(c => c.Id == created.Id, ct).ConfigureAwait(false);
        var linked = await _db.ClientIdentities.AsNoTracking().SingleOrDefaultAsync(i => i.Id == binding.Id, ct).ConfigureAwait(false);
        if (stored is null || linked is null || stored.TenantId != credential.TenantId || stored.OwnerUsername != credential.OwnerUsername
            || stored.ClientName != created.ClientName || stored.PasswordHash != created.PasswordHash || !stored.Enabled
            || linked.TenantId != credential.TenantId || linked.CredentialId != credential.Id || linked.ClientId != stored.Id
            || linked.ClientName != stored.ClientName || linked.MachineFingerprint != binding.MachineFingerprint || linked.OsUser != binding.OsUser) throw StartupChanged();
        return (credential, stored, linked);
    }

    private static ArgumentException StartupChanged() => new("客户端凭证或身份已变更或已停用，请重新认证");
}
