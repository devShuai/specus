using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

/// <summary>
/// An account that still owns clients or access credentials is not deleted (management-accounts.md
/// section 7.1): answered 409 with both counts, so the administrator knows what to delete or hand over.
/// </summary>
public sealed class AccountStillOwnsResourcesException(long clients, long credentials)
    : Exception($"该账号仍拥有 {clients} 个客户端、{credentials} 个接入凭证，需先转移或删除")
{
    public long Clients { get; } = clients;
    public long Credentials { get; } = credentials;
}

public sealed class ManagementUserService
{
    private readonly SpecusDbContext _db;
    private readonly AuthOptions _auth;
    private readonly HttpShareService _shares;
    private readonly ILogger<ManagementUserService>? _logger;

    public ManagementUserService(SpecusDbContext db, IOptions<AuthOptions> auth, HttpShareService shares,
        ILogger<ManagementUserService>? logger = null)
    {
        _db = db;
        _auth = auth.Value;
        _shares = shares;
        _logger = logger;
    }

    /// <summary>
    /// Password login (protocol/spec/management-accounts.md section 4). With a tenant the name is
    /// looked up in that tenant only; without one the default tenant answers first, and only when
    /// it has no such login name does an account whose key is the name (an account that predates
    /// login names) answer, provided exactly one does.
    /// </summary>
    public async Task<LoginUser?> AuthenticateAsync(string? username, string? password, string? tenantId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(username) || password is null)
        {
            return null;
        }

        var normalized = NormalizeUsername(username);
        string? requestedTenant = null;
        if (!string.IsNullOrWhiteSpace(tenantId) && !TryNormalizeRequestedTenant(tenantId, out requestedTenant))
        {
            return null;
        }
        var defaultTenant = DefaultTenant;
        if (string.Equals(normalized, _auth.Username, StringComparison.OrdinalIgnoreCase)
            && (requestedTenant is null || string.Equals(requestedTenant, defaultTenant, StringComparison.Ordinal)))
        {
            return IsAdminPasswordValid(normalized, password) ? BuiltInAdminUser() : null;
        }

        var user = requestedTenant is not null
            ? await FindByLoginNameAsync(_db.ManagementUsers.AsNoTracking(), requestedTenant, normalized,
                cancellationToken).ConfigureAwait(false)
            : await FindByLoginNameAsync(_db.ManagementUsers.AsNoTracking(), defaultTenant, normalized,
                    cancellationToken).ConfigureAwait(false)
              ?? await FindUniqueLegacyAccountAsync(normalized, cancellationToken).ConfigureAwait(false);
        if (user is null || !user.Enabled)
        {
            return null;
        }
        var verification = PasswordHasher.Verify(password, user.PasswordHash);
        if (!verification.Matches)
        {
            return null;
        }
        // A successful login is the only moment the plaintext exists, so it is the only chance to
        // retire a legacy or under-cost hash. Failing to persist must not fail the login: the user
        // is authenticated either way and the old hash still works next time.
        if (verification is { NeedsUpgrade: true, UpgradedHash: not null })
        {
            await UpgradeStoredPasswordAsync(user.Username, verification.UpgradedHash, cancellationToken)
                .ConfigureAwait(false);
        }
        return ToLoginUser(user);
    }

    /// <summary>
    /// Rewrites a stored password hash that verified but is legacy or below the current cost.
    /// Best effort: the caller is already authenticated, and the old hash keeps working.
    /// </summary>
    private async Task UpgradeStoredPasswordAsync(string accountKey, string upgradedHash,
        CancellationToken cancellationToken)
    {
        try
        {
            var tracked = await _db.ManagementUsers
                .FirstOrDefaultAsync(u => u.Username == accountKey, cancellationToken)
                .ConfigureAwait(false);
            if (tracked is null)
            {
                return;
            }
            tracked.PasswordHash = upgradedHash;
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            _logger?.LogWarning(error, "password hash upgrade failed for account {AccountKey}", accountKey);
        }
    }

    /// <summary>
    /// Resolves a verified OIDC identity by immutable issuer/subject. This intentionally mirrors
    /// Java: an identity already bound answers from any tenant; otherwise the first login may bind
    /// an enabled account with the same login name in the default tenant, or else provisions a
    /// least-privileged USER there. Accounts of other tenants never take part, not even to block
    /// the new one (protocol/spec/management-accounts.md section 9).
    /// </summary>
    public async Task<LoginUser?> ResolveOrProvisionOidcUserAsync(string? issuer, string? subject,
        string? preferredUsername, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(issuer)
            || string.IsNullOrWhiteSpace(subject)
            || string.IsNullOrWhiteSpace(preferredUsername))
        {
            return null;
        }

        var normalizedIssuer = issuer.Trim();
        var normalizedSubject = subject.Trim();
        if (normalizedIssuer.Length > 255 || normalizedSubject.Length > 255)
        {
            return null;
        }

        string username;
        try
        {
            username = NormalizeUsername(preferredUsername);
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (string.Equals(username, _auth.Username, StringComparison.OrdinalIgnoreCase))
        {
            // The configured break-glass administrator is never claimable by an external IdP.
            return null;
        }

        var identityKey = OidcIdentityKey(normalizedIssuer, normalizedSubject);
        var bound = await _db.ManagementUsers.AsNoTracking()
            .FirstOrDefaultAsync(user => user.OidcIdentityKey == identityKey, cancellationToken)
            .ConfigureAwait(false);
        if (bound is not null)
        {
            return IsExactEnabledOidcBinding(bound, normalizedIssuer, normalizedSubject, identityKey)
                && !IsBuiltInAdminName(bound.EffectiveLoginName())
                ? ToLoginUser(bound)
                : null;
        }

        var tenantId = DefaultTenant;
        var existing = await FindByLoginNameAsync(_db.ManagementUsers.AsNoTracking(), tenantId, username,
                cancellationToken)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            if (!existing.Enabled)
            {
                return null;
            }
            if (!string.IsNullOrWhiteSpace(existing.OidcIssuer)
                || !string.IsNullOrWhiteSpace(existing.OidcSubject))
            {
                return string.Equals(existing.OidcIdentityKey, identityKey, StringComparison.Ordinal)
                    ? ToLoginUser(existing)
                    : null;
            }

            // Compare-and-set on the account key makes two simultaneous first logins for the same
            // imported login name deterministic: exactly one immutable issuer/subject wins the binding.
            var updated = await _db.ManagementUsers
                .Where(user => user.Username == existing.Username
                    && user.Enabled
                    && (user.OidcIssuer == null || user.OidcIssuer == string.Empty)
                    && (user.OidcSubject == null || user.OidcSubject == string.Empty)
                    && (user.OidcIdentityKey == null || user.OidcIdentityKey == string.Empty))
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(user => user.OidcIssuer, normalizedIssuer)
                    .SetProperty(user => user.OidcSubject, normalizedSubject)
                    .SetProperty(user => user.OidcIdentityKey, identityKey)
                    .SetProperty(user => user.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken)
                .ConfigureAwait(false);
            var winner = await _db.ManagementUsers.AsNoTracking()
                .FirstOrDefaultAsync(user => user.Username == existing.Username, cancellationToken)
                .ConfigureAwait(false);
            return updated == 1
                   && winner is not null
                   && IsExactEnabledOidcBinding(winner, normalizedIssuer, normalizedSubject,
                       identityKey)
                ? ToLoginUser(winner)
                : winner is not null
                  && IsExactEnabledOidcBinding(winner, normalizedIssuer, normalizedSubject,
                      identityKey)
                    ? ToLoginUser(winner)
                    : null;
        }

        var now = DateTimeOffset.UtcNow;
        var user = new ManagementUser
        {
            Username = NewAccountKey(),
            LoginName = username,
            LoginNameNormalized = ManagementUser.NormalizeLoginName(username),
            TenantId = tenantId,
            PasswordHash = PasswordHasher.Hash(PasswordHasher.GeneratePassword()),
            OidcIssuer = normalizedIssuer,
            OidcSubject = normalizedSubject,
            OidcIdentityKey = identityKey,
            Role = ManagementRole.User,
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.ManagementUsers.Add(user);
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException)
        {
            // A concurrent first login may have inserted the same immutable identity (or taken the
            // login name). Clear the failed unit of work and resolve the winner instead of creating
            // a second binding.
            _db.Entry(user).State = EntityState.Detached;
            var concurrent = await _db.ManagementUsers.AsNoTracking()
                .FirstOrDefaultAsync(item => item.OidcIdentityKey == identityKey, cancellationToken)
                .ConfigureAwait(false);
            return concurrent is not null
                   && !IsBuiltInAdminName(concurrent.EffectiveLoginName())
                   && IsExactEnabledOidcBinding(concurrent, normalizedIssuer, normalizedSubject,
                       identityKey)
                ? ToLoginUser(concurrent)
                : null;
        }
        return ToLoginUser(user);
    }

    /// <summary>
    /// Resolves an already-bound external identity for direct OIDC bearer authentication. This
    /// path never provisions users and always reloads the current local tenant, role and status.
    /// </summary>
    public async Task<LoginUser?> ResolveBoundOidcUserAsync(string? issuer, string? subject,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        {
            return null;
        }
        var normalizedIssuer = issuer.Trim();
        var normalizedSubject = subject.Trim();
        if (normalizedIssuer.Length > 255 || normalizedSubject.Length > 255)
        {
            return null;
        }
        var identityKey = OidcIdentityKey(normalizedIssuer, normalizedSubject);
        var user = await _db.ManagementUsers.AsNoTracking()
            .FirstOrDefaultAsync(item => item.OidcIdentityKey == identityKey, cancellationToken)
            .ConfigureAwait(false);
        if (user is null
            || IsBuiltInAdminName(user.EffectiveLoginName())
            || !IsExactEnabledOidcBinding(user, normalizedIssuer, normalizedSubject, identityKey))
        {
            return null;
        }
        return ToLoginUser(user);
    }

    /// <summary>
    /// Re-resolves a local token's <c>sub</c> and <c>tenant_id</c> claims against the current
    /// configuration and database, for every request and before a refresh (Java
    /// <c>resolveLocalTokenUser</c>). With a tenant the subject is a login name of that tenant;
    /// without one the token predates tenant-scoped login names and its subject is an account key,
    /// looked up exactly. Tenant, role and enabled state always come from the account record.
    /// </summary>
    public Task<LoginUser?> ResolveLocalTokenUserAsync(string? subject, string? tenantId,
        CancellationToken cancellationToken) =>
        ResolveLocalTokenUserAsync(subject, tenantId, accountKey: null, cancellationToken);

    /// <summary>
    /// <paramref name="accountKey"/> is the token's <c>uid</c> claim. With one, the token resolves
    /// only to the account row whose key is exactly that value, never to the built-in administrator:
    /// the token of a deleted account must not pass to a later account of the same login name.
    /// Without one (tokens minted before the claim existed, and the built-in admin's) the subject and
    /// tenant resolve as before, until the token expires.
    /// </summary>
    public async Task<LoginUser?> ResolveLocalTokenUserAsync(string? subject, string? tenantId,
        string? accountKey, CancellationToken cancellationToken)
    {
        string normalized;
        try
        {
            normalized = NormalizeUsername(subject);
        }
        catch (ArgumentException)
        {
            return null;
        }
        string? requestedTenant = null;
        if (!string.IsNullOrWhiteSpace(tenantId) && !TryNormalizeRequestedTenant(tenantId, out requestedTenant))
        {
            return null;
        }

        var boundToAccount = !string.IsNullOrEmpty(accountKey);
        if (!boundToAccount
            && IsBuiltInAdminName(normalized)
            && (requestedTenant is null || string.Equals(requestedTenant, DefaultTenant, StringComparison.Ordinal)))
        {
            if (!_auth.PasswordLoginEnabled || string.IsNullOrWhiteSpace(_auth.Password))
            {
                return null;
            }
            return BuiltInAdminUser();
        }

        var user = requestedTenant is not null
            ? await FindByLoginNameAsync(_db.ManagementUsers.AsNoTracking(), requestedTenant, normalized,
                cancellationToken).ConfigureAwait(false)
            : await _db.ManagementUsers.AsNoTracking()
                .FirstOrDefaultAsync(item => item.Username == normalized, cancellationToken)
                .ConfigureAwait(false);
        if (user is not { Enabled: true })
        {
            return null;
        }
        // Compared here rather than in SQL, so a case-insensitive collation cannot relax it.
        return !boundToAccount || string.Equals(user.Username, accountKey, StringComparison.Ordinal)
            ? ToLoginUser(user)
            : null;
    }

    public async Task<ManagementUserView> CurrentUserAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        if (context.BuiltInAdmin)
        {
            var now = DateTimeOffset.UtcNow.ToString("O");
            return new ManagementUserView(_auth.Username, context.TenantId, "ADMIN",
                Admin: true, BuiltIn: true, Enabled: true, now, now);
        }

        var user = await FindByLoginNameAsync(_db.ManagementUsers.AsNoTracking(), context.TenantId,
                context.Username, cancellationToken)
            .ConfigureAwait(false);
        return user is null
            ? new ManagementUserView(context.Username, context.TenantId,
                ManagementContext.RoleWire(context.Role), context.IsAdmin,
                BuiltIn: false, Enabled: true, CreatedAt: string.Empty, UpdatedAt: string.Empty)
            : ToView(user);
    }

    public async Task<IReadOnlyList<ManagementUserView>> ListUsersAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var views = new List<ManagementUserView>();
        // The built-in admin belongs to the default tenant only: it signs in there and its tokens
        // resolve there, so another tenant's list does not show it as one of its accounts.
        if (string.Equals(context.TenantId, DefaultTenant, StringComparison.Ordinal))
        {
            var now = DateTimeOffset.UtcNow.ToString("O");
            views.Add(new ManagementUserView(_auth.Username, DefaultTenant, "ADMIN", Admin: true,
                BuiltIn: true, Enabled: true, now, now));
        }
        var users = await _db.ManagementUsers.AsNoTracking()
            .Where(u => u.TenantId == context.TenantId)
            .OrderBy(u => u.LoginName)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        views.AddRange(users.Select(ToView));
        return views.OrderByDescending(v => v.BuiltIn)
            .ThenBy(v => v.Username, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Creates an account in the caller's tenant. Only that tenant is checked for the login name:
    /// an account of the same name in another tenant is no conflict and is never looked at, so the
    /// answer cannot reveal it. The new account's key is a random UUID.
    /// </summary>
    public async Task<ManagementUserView> CreateUserAsync(ManagementContext context, UserMutation request,
        CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var username = NormalizeUsername(request.Username);
        if (IsBuiltInAdminName(username))
        {
            throw new ArgumentException("内置 admin 用户不能重复创建");
        }
        var loginNameNormalized = ManagementUser.NormalizeLoginName(username);
        if (await _db.ManagementUsers.AsNoTracking()
                .AnyAsync(u => u.TenantId == context.TenantId && u.LoginNameNormalized == loginNameNormalized,
                    cancellationToken)
                .ConfigureAwait(false))
        {
            throw CreateConflict(context, username);
        }

        var now = DateTimeOffset.UtcNow;
        var user = new ManagementUser
        {
            Username = NewAccountKey(),
            LoginName = username,
            LoginNameNormalized = loginNameNormalized,
            TenantId = context.TenantId,
            PasswordHash = PasswordHasher.Hash(RequirePassword(request.Password)),
            Role = ManagementContext.ParseRole(request.Role),
            Enabled = request.Enabled ?? true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.ManagementUsers.Add(user);
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException)
        {
            // A concurrent create in the same tenant won the unique (tenant_id, login_name_normalized).
            _db.Entry(user).State = EntityState.Detached;
            throw CreateConflict(context, username);
        }
        return ToView(user);
    }

    public async Task<ManagementUserView> UpdateUserAsync(ManagementContext context, string username,
        UserMutation request, CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var normalized = NormalizeUsername(username);
        if (IsBuiltInAdminName(normalized))
        {
            throw new ArgumentException("内置 admin 用户只能通过配置文件修改");
        }
        var user = await RequireMutableUserInTenantAsync(context, normalized, "update", cancellationToken)
            .ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(request.Password))
        {
            user.PasswordHash = PasswordHasher.Hash(RequirePassword(request.Password));
        }
        if (!string.IsNullOrWhiteSpace(request.Role))
        {
            user.Role = ManagementContext.ParseRole(request.Role);
        }
        if (request.Enabled is not null)
        {
            user.Enabled = request.Enabled.Value;
        }
        user.UpdatedAt = DateTimeOffset.UtcNow;
        // Disabling a user or changing its role ends the shares it created that it could no longer
        // create now, in the same transaction.
        List<string> revokedShares;
        await using (var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
                         .ConfigureAwait(false))
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            revokedShares = await _shares.OnUserChangedAsync(context.Username, user.EffectiveLoginName(),
                user.TenantId, cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        _shares.CutStreams(revokedShares);
        return ToView(user);
    }

    /// <summary>Deletes an account of the caller's tenant and returns its identity: tenant and login name.</summary>
    public async Task<(string TenantId, string Username)> DeleteUserAsync(ManagementContext context,
        string username, CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var normalized = NormalizeUsername(username);
        if (IsBuiltInAdminName(normalized))
        {
            throw new ArgumentException("内置 admin 用户不能删除");
        }
        var user = await RequireMutableUserInTenantAsync(context, normalized, "delete", cancellationToken)
            .ConfigureAwait(false);
        // Everything keyed by the account records its identity: the tenant and the login name.
        var tenantId = ManagementContext.NormalizeTenant(user.TenantId);
        var loginName = user.EffectiveLoginName();
        // The user's shares end with it: a share records its creator by name, and a later user of
        // the same name must not inherit them.
        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);
        // Clients and credentials carry tunnels in use: the administrator deletes or hands them over
        // first, as a later account of the same name would own them (management-accounts.md 7.1).
        var clients = await _db.ClientAccounts
            .LongCountAsync(client => client.TenantId == tenantId && client.OwnerUsername == loginName,
                cancellationToken)
            .ConfigureAwait(false);
        var credentials = await _db.ClientCredentials
            .LongCountAsync(credential => credential.TenantId == tenantId && credential.OwnerUsername == loginName,
                cancellationToken)
            .ConfigureAwait(false);
        if (clients > 0 || credentials > 0)
        {
            _logger?.LogWarning(
                "管理用户delete被拒绝: actor={Actor}, tenant={Tenant}, target={Target}, reason=仍拥有客户端{Clients}个、接入凭证{Credentials}个",
                context.Username, tenantId, loginName, clients, credentials);
            throw new AccountStillOwnsResourcesException(clients, credentials);
        }
        await ForgetOwnedDataAsync(tenantId, loginName, context.Username, cancellationToken).ConfigureAwait(false);
        // The workbench lists are personal history: they go with the account row, so an account
        // created later under the same name starts empty.
        await WorkbenchService.DeleteIdentityAsync(_db, tenantId, loginName, cancellationToken)
            .ConfigureAwait(false);
        // The registered email points at the account key and goes with the account, so the address
        // can register again once the transaction commits.
        var accountKey = user.Username;
        await _db.ManagementUserEmails
            .Where(email => email.Username == accountKey)
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
        _db.ManagementUsers.Remove(user);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        var revokedShares = await _shares.OnUserChangedAsync(context.Username, loginName, tenantId,
            cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        _shares.CutStreams(revokedShares);
        return (tenantId, loginName);
    }

    /// <summary>
    /// The rest of what a deleted account's identity owns, in the deletion's transaction
    /// (management-accounts.md section 7.1). Diagram documents, download grants and download usage
    /// go. Attachments expire now, so nothing can complete, download or count them any more and the
    /// expiry scan deletes their objects (the row is the only record of the object). Peer device rows
    /// of clients that no longer exist go. Peer ACLs and egress policies decide how other people's
    /// clients connect: they stay, owned by <paramref name="actor"/> from now on.
    /// </summary>
    private async Task ForgetOwnedDataAsync(string tenantId, string loginName, string actor,
        CancellationToken cancellationToken)
    {
        await _db.UserDiagramDocuments
            .Where(document => document.TenantId == tenantId && document.OwnerUsername == loginName)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        await _db.TransferAttachments
            .Where(attachment => attachment.TenantId == tenantId && attachment.OwnerUsername == loginName
                && attachment.Status != TransferAttachmentService.StatusExpired && attachment.ExpiresAt > now)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(attachment => attachment.ExpiresAt, now)
                .SetProperty(attachment => attachment.UploadExpiresAt, now)
                .SetProperty(attachment => attachment.UpdatedAt, now), cancellationToken)
            .ConfigureAwait(false);
        await _db.TransferAttachmentDownloadGrants
            .Where(grant => grant.TenantId == tenantId && grant.Username == loginName)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await _db.TransferAttachmentDownloadUsages
            .Where(usage => usage.TenantId == tenantId && usage.Username == loginName)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await _db.PeerMeshDevices
            .Where(device => device.TenantId == tenantId && device.OwnerUsername == loginName
                && !_db.ClientAccounts.Any(client => client.Id == device.ClientId))
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await _db.PeerMeshAcls
            .Where(acl => acl.TenantId == tenantId && acl.OwnerUsername == loginName)
            .ExecuteUpdateAsync(setters => setters.SetProperty(acl => acl.OwnerUsername, actor), cancellationToken)
            .ConfigureAwait(false);
        await _db.PeerMeshEgressPolicies
            .Where(policy => policy.TenantId == tenantId && policy.OwnerUsername == loginName)
            .ExecuteUpdateAsync(setters => setters.SetProperty(policy => policy.OwnerUsername, actor),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public static void RequireAdmin(ManagementContext context)
    {
        if (!context.IsAdmin)
        {
            throw new UnauthorizedAccessException("需要 admin 权限");
        }
    }

    /// <summary>
    /// The account with this login name in this tenant: the lookup behind every by-name account
    /// reference (password login, token subjects, management mutations, share creators). Names are
    /// compared in their canonical form, tenants exactly.
    /// </summary>
    internal static Task<ManagementUser?> FindByLoginNameAsync(IQueryable<ManagementUser> users,
        string tenantId, string loginName, CancellationToken cancellationToken)
    {
        var loginNameNormalized = ManagementUser.NormalizeLoginName(loginName);
        return users.FirstOrDefaultAsync(
            user => user.TenantId == tenantId && user.LoginNameNormalized == loginNameNormalized,
            cancellationToken);
    }

    /// <summary>
    /// Bare-name login of an account that predates login names: its account key equals the name,
    /// ignoring case. Exactly one such account answers; none or several (the same name in several
    /// tenants) fail closed, like a wrong password. Accounts created since have UUID keys and are
    /// never found here.
    /// </summary>
    private async Task<ManagementUser?> FindUniqueLegacyAccountAsync(string accountKey,
        CancellationToken cancellationToken)
    {
        var folded = ManagementUser.NormalizeLoginName(accountKey);
        // SQLite's lower() folds ASCII only, so the candidates also include rows whose canonical
        // login name matches (a legacy row's login name is its account key), and the comparison
        // itself is made here with the same folding as every other name comparison.
        var candidates = await _db.ManagementUsers.AsNoTracking()
            .Where(user => user.LoginNameNormalized == folded || user.Username.ToLower() == folded)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var matches = candidates
            .Where(user => string.Equals(ManagementUser.NormalizeLoginName(user.Username), folded,
                StringComparison.Ordinal))
            .Take(2)
            .ToList();
        return matches.Count == 1 ? matches[0] : null;
    }

    /// <summary>
    /// Mutation targets must belong to the acting administrator's tenant. A missing user and a
    /// user that only exists in another tenant answer the same, so no tenant can probe another's
    /// login names; the refused attempt is still logged.
    /// </summary>
    private async Task<ManagementUser> RequireMutableUserInTenantAsync(ManagementContext context,
        string loginName, string action, CancellationToken cancellationToken)
    {
        var user = await FindByLoginNameAsync(_db.ManagementUsers, context.TenantId, loginName,
                cancellationToken)
            .ConfigureAwait(false);
        if (user is null)
        {
            _logger?.LogWarning(
                "management user {Action} refused: actor={Actor}, tenant={Tenant}, target={Target}, reason=not in the acting tenant or missing",
                action, context.Username, context.TenantId, loginName);
            throw new ArgumentException("用户不存在: " + loginName);
        }
        return user;
    }

    private ArgumentException CreateConflict(ManagementContext context, string loginName)
    {
        _logger?.LogWarning(
            "management user create refused: actor={Actor}, tenant={Tenant}, target={Target}, reason=login name taken in the acting tenant",
            context.Username, context.TenantId, loginName);
        return new ArgumentException("用户名已存在: " + loginName);
    }

    private string DefaultTenant => ManagementContext.NormalizeTenant(_auth.TenantId);

    private bool IsBuiltInAdminName(string? username) =>
        username is not null && string.Equals(username.Trim(), _auth.Username, StringComparison.OrdinalIgnoreCase);

    private LoginUser BuiltInAdminUser() =>
        new(_auth.Username, DefaultTenant, ManagementRole.Admin, BuiltInAdmin: true);

    /// <summary>A tenant given by a caller (login body, token claim): trimmed, at most 80 characters.</summary>
    private static bool TryNormalizeRequestedTenant(string tenantId, out string? normalized)
    {
        var trimmed = tenantId.Trim();
        if (trimmed.Length is 0 or > 80)
        {
            normalized = null;
            return false;
        }
        normalized = trimmed;
        return true;
    }

    private bool IsAdminPasswordValid(string username, string password) =>
        _auth.PasswordLoginEnabled
        && !string.IsNullOrWhiteSpace(_auth.Password)
        && ConstantTimeEquals(_auth.Username, username)
        && ConstantTimeEquals(_auth.Password, password);

    private static bool ConstantTimeEquals(string expected, string actual)
    {
        var expectedHash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(expected));
        var actualHash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(actual));
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }

    private static string NormalizeUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("username cannot be blank");
        }
        var normalized = username.Trim();
        if (normalized.Length > 80)
        {
            throw new ArgumentException("username is too long");
        }
        return normalized;
    }

    private static string RequirePassword(string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("password cannot be blank");
        }
        var normalized = password.Trim();
        if (normalized.Length > 120)
        {
            throw new ArgumentException("password is too long");
        }
        return normalized;
    }

    /// <summary>The opaque primary key of an account created now: a random lower-case UUID.</summary>
    internal static string NewAccountKey() => Guid.NewGuid().ToString();

    private static string OidcIdentityKey(string issuer, string subject)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData(System.Text.Encoding.UTF8.GetBytes(issuer));
        digest.AppendData([0]);
        digest.AppendData(System.Text.Encoding.UTF8.GetBytes(subject));
        return Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>
    /// The identity a principal carries is the login name, never the account key; the key only
    /// travels in the token's <c>uid</c> claim.
    /// </summary>
    internal static LoginUser ToLoginUser(ManagementUser user) => new(
        user.EffectiveLoginName(),
        ManagementContext.NormalizeTenant(user.TenantId),
        user.Role,
        BuiltInAdmin: false,
        AccountKey: user.Username);

    private static bool IsExactEnabledOidcBinding(ManagementUser user, string issuer,
        string subject, string identityKey) =>
        user.Enabled
        && string.Equals(user.OidcIssuer, issuer, StringComparison.Ordinal)
        && string.Equals(user.OidcSubject, subject, StringComparison.Ordinal)
        && string.Equals(user.OidcIdentityKey, identityKey, StringComparison.Ordinal);

    private static ManagementUserView ToView(ManagementUser user)
    {
        var role = user.Role == ManagementRole.Admin ? "ADMIN" : "USER";
        return new ManagementUserView(user.EffectiveLoginName(), ManagementContext.NormalizeTenant(user.TenantId),
            role, user.Role == ManagementRole.Admin, BuiltIn: false, user.Enabled,
            user.CreatedAt.ToString("O"), user.UpdatedAt.ToString("O"));
    }
}

/// <summary>
/// A resolved management principal. <see cref="Username"/> is the login name (the built-in
/// administrator's configured name), never the opaque account key.
/// </summary>
/// <summary>A resolved principal; <see cref="AccountKey"/> is null only for the built-in admin.</summary>
public sealed record LoginUser(string Username, string TenantId, ManagementRole Role, bool BuiltInAdmin,
    string? AccountKey = null);
