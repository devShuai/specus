namespace Specus.Server.Data.Entities;

public enum ManagementRole
{
    Admin,
    User,
}

public sealed class ManagementUser
{
    /// <summary>
    /// Opaque account key (the primary key, column <c>username</c>). Accounts that existed before
    /// tenant-scoped login names keep their historic username here; accounts created since get a
    /// random UUID. It is never shown by the management API (protocol/spec/management-accounts.md).
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Tenant-scoped login name as entered: what password login takes, what the API returns as
    /// <c>username</c> and what tokens and owner columns record. Nullable only for rows written
    /// before the column existed; <see cref="SpecusDbContext"/> fills it on every write.
    /// </summary>
    public string? LoginName { get; set; }

    /// <summary><see cref="LoginName"/> trimmed and lower-cased; unique within a tenant.</summary>
    public string? LoginNameNormalized { get; set; }

    public string TenantId { get; set; } = "default";
    public string PasswordHash { get; set; } = string.Empty;
    public string? OidcIssuer { get; set; }
    public string? OidcSubject { get; set; }
    public string? OidcIdentityKey { get; set; }
    public ManagementRole Role { get; set; } = ManagementRole.User;
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    /// <summary>The login name; a row written before login names existed answers with its account key.</summary>
    public string EffectiveLoginName() => string.IsNullOrWhiteSpace(LoginName) ? Username : LoginName;

    /// <summary>The canonical form every by-name account lookup compares (<c>login_name_normalized</c>).</summary>
    public static string NormalizeLoginName(string loginName) => loginName.Trim().ToLowerInvariant();
}
