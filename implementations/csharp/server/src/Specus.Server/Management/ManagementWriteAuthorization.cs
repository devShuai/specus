using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Persistence;

namespace Specus.Server.Management;

// Captured only from the already verified principal. This is not a mutation DTO and is never
// resolved again by a reusable login name after the request has crossed authentication.
internal sealed record ManagementPrincipalBinding(string? AccountKey, string? ExternalIssuer, string? ExternalSubject)
{
    internal bool MatchesExternalIdentity(ManagementUser current)
    {
        if (ExternalSubject is null) return true;
        if (ExternalIssuer is null || current.OidcIssuer != ExternalIssuer || current.OidcSubject != ExternalSubject) return false;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(ExternalIssuer)); hash.AppendData([0]);
        hash.AppendData(Encoding.UTF8.GetBytes(ExternalSubject));
        return current.OidcIdentityKey == Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}

internal static class ManagementWriteAuthorization
{
    internal static async Task<ManagementContext> LockAsync(SpecusDbContext db, AuthOptions auth,
        ManagementContext original, CancellationToken ct)
    {
        var binding = original.Principal;
        if (original.BuiltInAdmin)
        {
            if (original.TenantId != ManagementContext.NormalizeTenant(auth.TenantId) || original.Username != auth.Username
                || !auth.PasswordLoginEnabled || string.IsNullOrWhiteSpace(auth.Password)
                || binding?.AccountKey is not null || binding?.ExternalSubject is not null)
                throw new UnauthorizedAccessException("管理身份已变更");
            return original with { Role = ManagementRole.Admin };
        }
        if (binding?.AccountKey is not { Length: > 0 } key) throw new UnauthorizedAccessException("缺少原管理账号身份");
        await ClientOwnershipWrite.LockAsync<ManagementUser>(db, key, original.TenantId, ct, nameof(ManagementUser.Username)).ConfigureAwait(false);
        var current = await db.ManagementUsers.AsNoTracking().SingleOrDefaultAsync(u => u.Username == key && u.TenantId == original.TenantId, ct).ConfigureAwait(false);
        if (current is null || current.Username != key || current.TenantId != original.TenantId || !current.Enabled
            || current.EffectiveLoginName() != original.Username || !binding.MatchesExternalIdentity(current))
            throw new UnauthorizedAccessException("管理身份已变更");
        return original with { Username = current.EffectiveLoginName(), Role = current.Role, BuiltInAdmin = false };
    }
}
