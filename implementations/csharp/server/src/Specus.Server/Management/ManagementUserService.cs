using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

public sealed class ManagementUserService
{
    private readonly SpecusDbContext _db;
    private readonly AuthOptions _auth;
    private readonly ILogger<ManagementUserService>? _logger;

    public ManagementUserService(SpecusDbContext db, IOptions<AuthOptions> auth,
        ILogger<ManagementUserService>? logger = null)
    {
        _db = db;
        _auth = auth.Value;
        _logger = logger;
    }

    public async Task<LoginUser?> AuthenticateAsync(string? username, string? password,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(username) || password is null)
        {
            return null;
        }

        var normalized = NormalizeUsername(username);
        if (string.Equals(normalized, _auth.Username, StringComparison.OrdinalIgnoreCase))
        {
            return IsAdminPasswordValid(normalized, password)
                ? new LoginUser(_auth.Username, ManagementContext.NormalizeTenant(_auth.TenantId),
                    ManagementRole.Admin, BuiltInAdmin: true)
                : null;
        }

        var user = await _db.ManagementUsers.AsNoTracking()
            .FirstOrDefaultAsync(u => u.Username.ToLower() == normalized.ToLower(), cancellationToken)
            .ConfigureAwait(false);
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
        return new LoginUser(user.Username, ManagementContext.NormalizeTenant(user.TenantId),
            user.Role, BuiltInAdmin: false);
    }

    /// <summary>
    /// Rewrites a stored password hash that verified but is legacy or below the current cost.
    /// Best effort: the caller is already authenticated, and the old hash keeps working.
    /// </summary>
    private async Task UpgradeStoredPasswordAsync(string username, string upgradedHash,
        CancellationToken cancellationToken)
    {
        try
        {
            var tracked = await _db.ManagementUsers
                .FirstOrDefaultAsync(u => u.Username == username, cancellationToken)
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
            _logger?.LogWarning(error, "password hash upgrade failed for {Username}", username);
        }
    }

    /// <summary>
    /// Resolves a verified OIDC identity by immutable issuer/subject. This intentionally mirrors
    /// Java: first login may bind an enabled imported username, otherwise it provisions a local
    /// least-privileged USER in the configured default tenant.
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
                && !string.Equals(bound.Username, _auth.Username, StringComparison.OrdinalIgnoreCase)
                ? ToLoginUser(bound)
                : null;
        }

        var existing = await _db.ManagementUsers.AsNoTracking()
            .FirstOrDefaultAsync(user => user.Username.ToLower() == username.ToLower(), cancellationToken)
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

            // Compare-and-set makes two simultaneous first logins for the same imported username
            // deterministic: exactly one immutable issuer/subject wins the binding.
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
            Username = username,
            TenantId = ManagementContext.NormalizeTenant(_auth.TenantId),
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
            // A concurrent first login may have inserted the same immutable identity. Clear the
            // failed unit of work and resolve the winner instead of creating a second binding.
            _db.Entry(user).State = EntityState.Detached;
            var concurrent = await _db.ManagementUsers.AsNoTracking()
                .FirstOrDefaultAsync(item => item.OidcIdentityKey == identityKey, cancellationToken)
                .ConfigureAwait(false);
            return concurrent is not null
                   && !string.Equals(concurrent.Username, _auth.Username,
                       StringComparison.OrdinalIgnoreCase)
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
            || string.Equals(user.Username, _auth.Username, StringComparison.OrdinalIgnoreCase)
            || !IsExactEnabledOidcBinding(user, normalizedIssuer, normalizedSubject, identityKey))
        {
            return null;
        }
        return ToLoginUser(user);
    }

    /// <summary>Reloads a local-token subject before issuing a refreshed token.</summary>
    public async Task<LoginUser?> ResolveRefreshUserAsync(string? username,
        CancellationToken cancellationToken)
    {
        string normalized;
        try
        {
            normalized = NormalizeUsername(username);
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (string.Equals(normalized, _auth.Username, StringComparison.OrdinalIgnoreCase))
        {
            if (!_auth.PasswordLoginEnabled || string.IsNullOrWhiteSpace(_auth.Password))
            {
                return null;
            }
            return new LoginUser(_auth.Username, ManagementContext.NormalizeTenant(_auth.TenantId),
                ManagementRole.Admin, BuiltInAdmin: true);
        }

        var user = await _db.ManagementUsers.AsNoTracking()
            .FirstOrDefaultAsync(item => item.Username.ToLower() == normalized.ToLower(),
                cancellationToken)
            .ConfigureAwait(false);
        return user is { Enabled: true } ? ToLoginUser(user) : null;
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

        var user = await _db.ManagementUsers.AsNoTracking()
            .FirstOrDefaultAsync(u => u.Username.ToLower() == context.Username.ToLower(),
                cancellationToken)
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
        var now = DateTimeOffset.UtcNow.ToString("O");
        var views = new List<ManagementUserView>
        {
            new(_auth.Username, context.TenantId, "ADMIN", Admin: true,
                BuiltIn: true, Enabled: true, now, now),
        };
        var users = await _db.ManagementUsers.AsNoTracking()
            .Where(u => u.TenantId == context.TenantId)
            .OrderBy(u => u.Username)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        views.AddRange(users.Select(ToView));
        return views.OrderByDescending(v => v.BuiltIn)
            .ThenBy(v => v.Username, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public async Task<ManagementUserView> CreateUserAsync(ManagementContext context, UserMutation request,
        CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var username = NormalizeUsername(request.Username);
        if (string.Equals(username, _auth.Username, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("内置 admin 用户不能重复创建");
        }
        if (await _db.ManagementUsers.AsNoTracking()
                .AnyAsync(u => u.Username.ToLower() == username.ToLower(), cancellationToken)
                .ConfigureAwait(false))
        {
            throw new ArgumentException("用户名已存在: " + username);
        }

        var now = DateTimeOffset.UtcNow;
        var user = new ManagementUser
        {
            Username = username,
            TenantId = context.TenantId,
            PasswordHash = PasswordHasher.Hash(RequirePassword(request.Password)),
            Role = ManagementContext.ParseRole(request.Role),
            Enabled = request.Enabled ?? true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.ManagementUsers.Add(user);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return ToView(user);
    }

    public async Task<ManagementUserView> UpdateUserAsync(ManagementContext context, string username,
        UserMutation request, CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var normalized = NormalizeUsername(username);
        if (string.Equals(normalized, _auth.Username, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("内置 admin 用户只能通过配置文件修改");
        }
        var user = await _db.ManagementUsers
            .FirstOrDefaultAsync(u => u.Username.ToLower() == normalized.ToLower(),
                cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException("用户不存在: " + normalized);
        if (!ManagementContext.SameTenant(user.TenantId, context.TenantId))
        {
            throw new ArgumentException("用户不存在: " + normalized);
        }
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
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return ToView(user);
    }

    public async Task DeleteUserAsync(ManagementContext context, string username,
        CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var normalized = NormalizeUsername(username);
        if (string.Equals(normalized, _auth.Username, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("内置 admin 用户不能删除");
        }
        var user = await _db.ManagementUsers
            .FirstOrDefaultAsync(u => u.Username.ToLower() == normalized.ToLower(),
                cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException("用户不存在: " + normalized);
        if (!ManagementContext.SameTenant(user.TenantId, context.TenantId))
        {
            throw new ArgumentException("用户不存在: " + normalized);
        }
        _db.ManagementUsers.Remove(user);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public static void RequireAdmin(ManagementContext context)
    {
        if (!context.IsAdmin)
        {
            throw new UnauthorizedAccessException("需要 admin 权限");
        }
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

    private static string OidcIdentityKey(string issuer, string subject)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData(System.Text.Encoding.UTF8.GetBytes(issuer));
        digest.AppendData([0]);
        digest.AppendData(System.Text.Encoding.UTF8.GetBytes(subject));
        return Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
    }

    private static LoginUser ToLoginUser(ManagementUser user) => new(
        user.Username,
        ManagementContext.NormalizeTenant(user.TenantId),
        user.Role,
        BuiltInAdmin: false);

    private static bool IsExactEnabledOidcBinding(ManagementUser user, string issuer,
        string subject, string identityKey) =>
        user.Enabled
        && string.Equals(user.OidcIssuer, issuer, StringComparison.Ordinal)
        && string.Equals(user.OidcSubject, subject, StringComparison.Ordinal)
        && string.Equals(user.OidcIdentityKey, identityKey, StringComparison.Ordinal);

    private static ManagementUserView ToView(ManagementUser user)
    {
        var role = user.Role == ManagementRole.Admin ? "ADMIN" : "USER";
        return new ManagementUserView(user.Username, ManagementContext.NormalizeTenant(user.TenantId),
            role, user.Role == ManagementRole.Admin, BuiltIn: false, user.Enabled,
            user.CreatedAt.ToString("O"), user.UpdatedAt.ToString("O"));
    }
}

public sealed record LoginUser(string Username, string TenantId, ManagementRole Role, bool BuiltInAdmin);
