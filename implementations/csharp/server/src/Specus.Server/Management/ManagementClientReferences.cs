using Microsoft.EntityFrameworkCore;
using Specus.Server.Data.Conversion;
using Specus.Server.Data.Entities;
using Specus.Server.Persistence;

namespace Specus.Server.Management;

public sealed partial class ManagementMutationService
{
    // Match signed HTTP startup and transfer: credential -> client -> identity/device.
    // An absent/deleted credential must not prevent management of its remaining client.
    private async Task<ClientAccount> LockClientWithIdentityLinksAsync(ManagementContext context, long id, CancellationToken ct)
    {
        var credentialIds = await _db.ClientIdentities.AsNoTracking().Where(i => i.ClientId == id)
            .Select(i => i.CredentialId).Distinct().OrderBy(i => i).ToArrayAsync(ct).ConfigureAwait(false);
        foreach (var credentialId in credentialIds)
            await ClientOwnershipWrite.LockAsync<ClientCredential>(_db, credentialId, context.TenantId, ct).ConfigureAwait(false);
        var account = await LockClientForWriteAsync(context, id, ct).ConfigureAwait(false);
        var identities = await _db.ClientIdentities.AsNoTracking().Where(i => i.ClientId == id).OrderBy(i => i.Id).ToListAsync(ct).ConfigureAwait(false);
        if (identities.Any(i => !credentialIds.Contains(i.CredentialId)))
            throw new ClientOwnerTransferException(409, "CLIENT_IDENTITY_CHANGED");
        foreach (var identity in identities.Where(i => string.Equals(i.TenantId, account.TenantId, StringComparison.Ordinal)))
            await ClientOwnershipWrite.LockAsync<ClientIdentity>(_db, identity.Id, account.TenantId, ct).ConfigureAwait(false);
        var peers = await _db.PeerMeshDevices.AsNoTracking().Where(p => p.ClientId == id).OrderBy(p => p.Id).ToListAsync(ct).ConfigureAwait(false);
        foreach (var peer in peers.Where(p => string.Equals(p.TenantId, account.TenantId, StringComparison.Ordinal)))
            await ClientOwnershipWrite.LockAsync<PeerMeshDevice>(_db, peer.Id, account.TenantId, ct).ConfigureAwait(false);
        return account;
    }

    private string ExactTenant(string column) => _db.Database.ProviderName switch
    {
        "MySql.EntityFrameworkCore" => $"CAST({column} AS BINARY)=CAST(@tenant AS BINARY)",
        "Npgsql.EntityFrameworkCore.PostgreSQL" => $"{column} COLLATE \"C\"=@tenant COLLATE \"C\"",
        "Microsoft.EntityFrameworkCore.Sqlite" => $"{column} COLLATE BINARY=@tenant COLLATE BINARY",
        _ => throw new NotSupportedException("unsupported client reference provider"),
    };

    private async Task RenameClientReferencesAsync(ClientAccount account, CancellationToken ct)
    {
        await RenameReferenceAsync<ClientIdentity>(account, "ClientId", "ClientName", false, false, ct).ConfigureAwait(false);
        await RenameReferenceAsync<PeerMeshDevice>(account, "ClientId", "ClientName", true, false, ct).ConfigureAwait(false);
        await RenameReferenceAsync<SpecusMapping>(account, "ClientId", "ClientName", true, true, ct).ConfigureAwait(false);
        await RenameReferenceAsync<HttpRouteMapping>(account, "ClientId", "ClientName", true, true, ct).ConfigureAwait(false);
        await RenameReferenceAsync<PeerMeshSharedService>(account, "ClientId", "ClientName", true, false, ct).ConfigureAwait(false);
        await RenameReferenceAsync<PeerMeshEgressPolicy>(account, "EgressClientId", "EgressClientName", true, false, ct).ConfigureAwait(false);
        await RenameReferenceAsync<TrafficUsage>(account, "ClientId", "ClientName", false, false, ct).ConfigureAwait(false);
        await RenameReferenceAsync<ResourceTrafficUsage>(account, "ClientId", "ClientName", false, false, ct).ConfigureAwait(false);

        // Both directions in one statement; lock overlapping ACL rows in a stable order.
        var acls = await _db.PeerMeshAcls.AsNoTracking().Where(a => a.SourceClientId == account.Id || a.TargetClientId == account.Id)
            .OrderBy(a => a.Id).ToListAsync(ct).ConfigureAwait(false);
        foreach (var acl in acls.Where(a => string.Equals(a.TenantId, account.TenantId, StringComparison.Ordinal)))
            await ClientOwnershipWrite.LockAsync<PeerMeshAcl>(_db, acl.Id, account.TenantId, ct).ConfigureAwait(false);
        var (table, source) = ClientOwnershipWrite.Identifiers<PeerMeshAcl>(_db, "SourceClientId");
        var target = ClientOwnershipWrite.Identifiers<PeerMeshAcl>(_db, "TargetClientId").Key;
        var sourceName = ClientOwnershipWrite.Identifiers<PeerMeshAcl>(_db, "SourceClientName").Key;
        var targetName = ClientOwnershipWrite.Identifiers<PeerMeshAcl>(_db, "TargetClientName").Key;
        var tenant = ClientOwnershipWrite.Identifiers<PeerMeshAcl>(_db, "TenantId").Key;
        var updated = ClientOwnershipWrite.Identifiers<PeerMeshAcl>(_db, "UpdatedAt").Key;
        await using var command = ClientOwnershipWrite.Command(_db,
            $"UPDATE {table} SET {sourceName}=CASE WHEN {source}=@id THEN @name ELSE {sourceName} END," +
            $"{targetName}=CASE WHEN {target}=@id THEN @name ELSE {targetName} END,{updated}=@now " +
            $"WHERE ({source}=@id OR {target}=@id) AND {ExactTenant(tenant)}",
            ("@id", account.Id), ("@name", account.ClientName), ("@now", IsoDateTimeOffsetConverter.Format(account.UpdatedAt)), ("@tenant", account.TenantId));
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private async Task RenameReferenceAsync<T>(ClientAccount account, string clientProperty, string nameProperty,
        bool timestamp, bool legacyNullTenant, CancellationToken ct)
    {
        var (table, client) = ClientOwnershipWrite.Identifiers<T>(_db, clientProperty);
        var name = ClientOwnershipWrite.Identifiers<T>(_db, nameProperty).Key;
        var tenant = ClientOwnershipWrite.Identifiers<T>(_db, "TenantId").Key;
        var stamp = timestamp ? $",{ClientOwnershipWrite.Identifiers<T>(_db, "UpdatedAt").Key}=@now" : "";
        var predicate = legacyNullTenant ? $"({ExactTenant(tenant)} OR {tenant} IS NULL)" : ExactTenant(tenant);
        await using var command = ClientOwnershipWrite.Command(_db,
            $"UPDATE {table} SET {name}=@name{stamp} WHERE {client}=@id AND {predicate}",
            ("@name", account.ClientName), ("@now", IsoDateTimeOffsetConverter.Format(account.UpdatedAt)), ("@id", account.Id), ("@tenant", account.TenantId));
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private async Task DeleteCurrentIdentityLinksAsync(ClientAccount account, CancellationToken ct)
    {
        var (table, client) = ClientOwnershipWrite.Identifiers<ClientIdentity>(_db, "ClientId");
        var tenant = ClientOwnershipWrite.Identifiers<ClientIdentity>(_db, "TenantId").Key;
        await using var command = ClientOwnershipWrite.Command(_db,
            $"DELETE FROM {table} WHERE {client}=@id AND {ExactTenant(tenant)}", ("@id", account.Id), ("@tenant", account.TenantId));
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}
