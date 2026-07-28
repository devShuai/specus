using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
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

    public ManagementUserService(SpecusDbContext db, IOptions<AuthOptions> auth)
    {
        _db = db;
        _auth = auth.Value;
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
        if (user is null || !user.Enabled || !PasswordHasher.Matches(password, user.PasswordHash))
        {
            return null;
        }
        return new LoginUser(user.Username, ManagementContext.NormalizeTenant(user.TenantId),
            user.Role, BuiltInAdmin: false);
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

    private static ManagementUserView ToView(ManagementUser user)
    {
        var role = user.Role == ManagementRole.Admin ? "ADMIN" : "USER";
        return new ManagementUserView(user.Username, ManagementContext.NormalizeTenant(user.TenantId),
            role, user.Role == ManagementRole.Admin, BuiltIn: false, user.Enabled,
            user.CreatedAt.ToString("O"), user.UpdatedAt.ToString("O"));
    }
}

public sealed record LoginUser(string Username, string TenantId, ManagementRole Role, bool BuiltInAdmin);
