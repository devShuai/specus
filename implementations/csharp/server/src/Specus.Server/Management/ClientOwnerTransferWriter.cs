using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Security;
using Specus.Server.Persistence;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.Server.Management;

// Constructed from the ALREADY verified bearer principal, never from a transfer request body.
internal sealed record OwnerTransferActor(ManagementContext Context, string? AccountKey,
    string? ExternalIssuer = null, string? ExternalSubject = null)
{
    internal static OwnerTransferActor From(HttpContext http, AuthOptions auth)
    {
        var subject = http.User.FindFirstValue("oidc_sub");
        return new(ManagementContext.From(http, auth), http.User.FindFirstValue(LocalTokenService.AccountKeyClaim),
            subject is null ? null : http.User.FindFirstValue("iss"), subject);
    }
}

internal sealed record OwnerTransferWriteResult(string Scope, string TargetUsername, long? CredentialId,
    IReadOnlyList<long> AffectedClientIds, bool Changed, bool AccessRetained);
internal sealed record OwnerTransferWriteOutcome(OwnerTransferWriteResult Response, long? AuditId);

// Internal core only. No POST is mounted until startup/CRUD/runtime writers participate in
// this database boundary and durable post-commit reconciliation is wired. No network/cache
// callback, token revocation, or unrelated tracked EF entity flush occurs in this transaction.
internal sealed class ClientOwnerTransferWriter(SpecusDbContext db, IOptions<AuthOptions> auth)
{
    private sealed class RangeChangedException : Exception;
    private sealed class TargetBinding
    {
        public bool Resolved { get; set; }
        public string? Key { get; set; }
    }

    internal async Task<OwnerTransferWriteOutcome> CommitAsync(OwnerTransferActor original, PathScope scope,
        string path, JsonElement request, CancellationToken cancellationToken)
    {
        AuthorizeAndValidateId(original.Context, 1);
        if (db.Database.CurrentTransaction is not null)
            throw new InvalidOperationException("ownership writer requires its own transaction");
        var target = new TargetBinding();
        for (var attempt = 0; ; attempt++)
        {
            try { return await CommitOnceAsync(original, scope, path, request, target, cancellationToken).ConfigureAwait(false); }
            catch (RangeChangedException) when (attempt < 3 && !cancellationToken.IsCancellationRequested) { }
        }
    }

    private async Task<OwnerTransferWriteOutcome> CommitOnceAsync(OwnerTransferActor original, PathScope scope,
        string path, JsonElement request, TargetBinding binding, CancellationToken ct)
    {
        // ReadCommitted matters on MySQL: a discovery read before a lock must not pin an old
        // RR snapshot. SQLite's non-deferred Serializable transaction owns the write reservation.
        await using var transaction = await ClientOwnershipWrite.BeginAsync(db, ct).ConfigureAwait(false);
        var hint = request.ValueKind == JsonValueKind.Object
                   && request.TryGetProperty("targetUsername", out var field) && field.ValueKind == JsonValueKind.String
            ? field.GetString() : null;
        var (actor, target) = await LockActorsAsync(original, hint, binding, ct).ConfigureAwait(false);
        var id = ClientOwnerTransferService.ParseId(actor, path);
        if (request.ValueKind != JsonValueKind.Object) throw Invalid();
        if (scope is not (PathScope.Single or PathScope.CredentialGroup)) throw Invalid();

        var reader = new ClientOwnerTransferService(db);
        var current = await reader.LoadAsync(actor, scope, id, ct).ConfigureAwait(false);
        var credentialIds = current.Credentials.Select(c => c.Id).Concat(current.Identities.Select(i => i.CredentialId))
            .Concat(scope == PathScope.CredentialGroup ? [id] : Array.Empty<long>()).ToHashSet();
        await LockIdsAsync<ClientCredential>(credentialIds, actor.TenantId, ct).ConfigureAwait(false);
        current = await reader.LoadAsync(actor, scope, id, ct).ConfigureAwait(false);
        var clientIds = current.Clients.Select(c => c.Id).Concat(current.Identities.Select(i => i.ClientId))
            .Concat(scope == PathScope.Single ? [id] : Array.Empty<long>()).ToHashSet();
        await LockIdsAsync<ClientAccount>(clientIds, actor.TenantId, ct).ConfigureAwait(false);
        current = await reader.LoadAsync(actor, scope, id, ct).ConfigureAwait(false);
        var identityIds = current.Identities.Select(i => i.Id).ToHashSet();
        var peerIds = current.Peers.Select(p => p.Id).ToHashSet();
        await LockIdsAsync<ClientIdentity>(identityIds, actor.TenantId, ct).ConfigureAwait(false);
        await LockIdsAsync<PeerMeshDevice>(peerIds, actor.TenantId, ct).ConfigureAwait(false);
        current = await reader.LoadAsync(actor, scope, id, ct).ConfigureAwait(false);
        var prepared = Prepare(actor, scope, id, request, current);
        // Preserve logical error precedence, then refuse to mutate newly discovered rows without
        // their prerequisites. Retry in a NEW transaction, with the target account key still pinned.
        if (current.Credentials.Any(c => !credentialIds.Contains(c.Id))
            || current.Clients.Any(c => !clientIds.Contains(c.Id))
            || current.Identities.Any(i => !identityIds.Contains(i.Id))
            || current.Peers.Any(p => !peerIds.Contains(p.Id))) throw new RangeChangedException();

        var canonical = IsBuiltInTarget(actor.TenantId, prepared.RequestedTargetUsername)
            ? auth.Value.Username
            : target is { Enabled: true } && target.TenantId == actor.TenantId
              && ManagementUser.NormalizeLoginName(target.EffectiveLoginName()) == ManagementUser.NormalizeLoginName(prepared.RequestedTargetUsername)
                ? target.EffectiveLoginName() : null;
        if (canonical is null) throw new ClientOwnerTransferException(400, "INVALID_TARGET_OWNER");
        var changed = current.Clients.Any(c => c.OwnerUsername != canonical)
                      || current.Credentials.Any(c => c.OwnerUsername != canonical)
                      || current.Peers.Any(p => p.OwnerUsername != canonical);
        var result = new OwnerTransferWriteResult(scope.WireName(), canonical, prepared.Preview.CredentialId,
            Array.AsReadOnly(prepared.Preview.AffectedClients.Select(c => c.Id).ToArray()), changed, true);
        long? auditId = null;
        if (changed)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var row in current.Clients) await WriteOwnerAsync<ClientAccount>(row.Id, actor.TenantId, canonical, now, ct).ConfigureAwait(false);
            foreach (var row in current.Credentials) await WriteOwnerAsync<ClientCredential>(row.Id, actor.TenantId, canonical, now, ct).ConfigureAwait(false);
            foreach (var row in current.Peers) await WriteOwnerAsync<PeerMeshDevice>(row.Id, actor.TenantId, canonical, now, ct).ConfigureAwait(false);
            auditId = ClientIdGenerator.NewId();
            var detail = JsonSerializer.Serialize(new
            {
                clients = current.Clients, credentials = current.Credentials, peerDevices = current.Peers,
                affectedClientIds = result.AffectedClientIds,
            }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            // Explicit SQL, not SaveChanges: the caller may have unrelated/stale tracked objects.
            await using var audit = Command("INSERT INTO client_owner_transfer_audit (id,tenant_id,occurred_at,actor,scope,path_id,target_username,credential_id,detail_json) VALUES (@id,@tenant,@at,@actor,@scope,@path,@target,@credential,@detail)",
                ("@id", auditId.Value), ("@tenant", actor.TenantId), ("@at", Stamp(now)), ("@actor", actor.Username),
                ("@scope", scope.WireName()), ("@path", id), ("@target", canonical),
                ("@credential", prepared.Preview.CredentialId), ("@detail", detail));
            if (await audit.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1)
                throw new InvalidOperationException("ownership audit was not inserted");
            var stored = await db.ClientOwnerTransferAudits.AsNoTracking().SingleOrDefaultAsync(a => a.Id == auditId.Value, ct).ConfigureAwait(false);
            if (stored is null || stored.TenantId != actor.TenantId || stored.Actor != actor.Username
                || stored.Scope != scope.WireName() || stored.PathId != id || stored.TargetUsername != canonical
                || stored.CredentialId != prepared.Preview.CredentialId || stored.DetailJson != detail
                || stored.OccurredAt != now)
                throw new InvalidOperationException("ownership audit postcondition failed");
        }
        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return new(result, auditId);
    }

    private async Task<(ManagementContext Actor, ManagementUser? Target)> LockActorsAsync(
        OwnerTransferActor original, string? requested, TargetBinding binding, CancellationToken ct)
    {
        var context = original.Context;
        var normalized = string.IsNullOrWhiteSpace(requested) ? null : ManagementUser.NormalizeLoginName(requested);
        if (!binding.Resolved)
        {
            if (normalized is { Length: <= 80 } && !IsReservedBuiltInName(context.TenantId, normalized))
            {
                var matches = await db.ManagementUsers.AsNoTracking().Where(u => u.TenantId == context.TenantId
                    && (u.LoginNameNormalized == normalized || (u.LoginNameNormalized == null && u.Username == requested)))
                    .ToListAsync(ct).ConfigureAwait(false);
                var exact = matches.Where(u => u.TenantId == context.TenantId
                    && ManagementUser.NormalizeLoginName(u.EffectiveLoginName()) == normalized).ToArray();
                if (exact.Length == 1) binding.Key = exact[0].Username;
            }
            binding.Resolved = true;
        }
        var keys = new[] { original.AccountKey, binding.Key }.Where(k => !string.IsNullOrEmpty(k))
            .Cast<string>().Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
        var users = new Dictionary<string, ManagementUser>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            await LockKeyAsync<ManagementUser>(nameof(ManagementUser.Username), key, context.TenantId, ct).ConfigureAwait(false);
            var user = await db.ManagementUsers.AsNoTracking().FirstOrDefaultAsync(u => u.Username == key && u.TenantId == context.TenantId, ct).ConfigureAwait(false);
            if (user is not null && user.Username == key && user.TenantId == context.TenantId) users[key] = user;
        }
        if (context.BuiltInAdmin)
        {
            if (!string.IsNullOrEmpty(original.AccountKey) || !IsBuiltInTarget(context.TenantId, context.Username)
                || context.Username != auth.Value.Username) throw new UnauthorizedAccessException("管理身份已变更");
        }
        else
        {
            if (original.AccountKey is null || !users.TryGetValue(original.AccountKey, out var actor)
                || !actor.Enabled || actor.EffectiveLoginName() != context.Username
                || !ExternalIdentityMatches(original, actor)) throw new UnauthorizedAccessException("管理身份已变更");
            context = context with { Username = actor.EffectiveLoginName(), Role = actor.Role, BuiltInAdmin = false };
        }
        AuthorizeAndValidateId(context, 1);
        return (context, binding.Key is not null && users.TryGetValue(binding.Key, out var target) ? target : null);
    }

    private static bool ExternalIdentityMatches(OwnerTransferActor original, ManagementUser current)
    {
        if (original.ExternalSubject is null) return true; // Local token: OIDC binding is not its authority.
        if (original.ExternalIssuer is null || current.OidcIssuer != original.ExternalIssuer
            || current.OidcSubject != original.ExternalSubject) return false;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(original.ExternalIssuer)); hash.AppendData([0]);
        hash.AppendData(Encoding.UTF8.GetBytes(original.ExternalSubject));
        return current.OidcIdentityKey == Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private bool IsReservedBuiltInName(string tenant, string name) => tenant == ManagementContext.NormalizeTenant(auth.Value.TenantId)
        && ManagementUser.NormalizeLoginName(name) == ManagementUser.NormalizeLoginName(auth.Value.Username);
    private bool IsBuiltInTarget(string tenant, string name) => IsReservedBuiltInName(tenant, name)
        && auth.Value.PasswordLoginEnabled && !string.IsNullOrWhiteSpace(auth.Value.Password);

    private async Task LockIdsAsync<T>(IEnumerable<long> ids, string tenant, CancellationToken ct)
    {
        foreach (var id in ids.Distinct().Order()) await LockKeyAsync<T>("Id", id, tenant, ct).ConfigureAwait(false);
    }

    private Task LockKeyAsync<T>(string keyProperty, object id, string tenant, CancellationToken ct) =>
        ClientOwnershipWrite.LockAsync<T>(db, id, tenant, ct, keyProperty);

    private async Task WriteOwnerAsync<T>(long id, string tenant, string target, DateTimeOffset now, CancellationToken ct)
    {
        var (table, key) = Identifiers<T>("Id");
        await using (var command = Command($"UPDATE {table} SET owner_username=@owner,updated_at=@at WHERE {key}=@id AND tenant_id=@tenant",
            ("@owner", target), ("@at", Stamp(now)), ("@id", id), ("@tenant", tenant)))
            _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        await using var check = Command($"SELECT tenant_id,owner_username FROM {table} WHERE {key}=@id AND tenant_id=@tenant",
            ("@id", id), ("@tenant", tenant));
        await using var reader = await check.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.GetString(0) != tenant || reader.IsDBNull(1)
            || reader.GetString(1) != target) throw new InvalidOperationException("ownership write postcondition failed");
    }

    private (string Table, string Key) Identifiers<T>(string property) => ClientOwnershipWrite.Identifiers<T>(db, property);

    private DbCommand Command(string text, params (string Name, object? Value)[] parameters)
        => ClientOwnershipWrite.Command(db, text, parameters);

    private static string Stamp(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);
    private static ClientOwnerTransferException Invalid() => new(400, "INVALID_TRANSFER_REQUEST");
}
