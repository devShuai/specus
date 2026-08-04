namespace Specus.Server.Data.Entities;

public enum ManagementRole
{
    Admin,
    User,
}

public sealed class ManagementUser
{
    public string Username { get; set; } = string.Empty;
    public string TenantId { get; set; } = "default";
    public string PasswordHash { get; set; } = string.Empty;
    public string? OidcIssuer { get; set; }
    public string? OidcSubject { get; set; }
    public string? OidcIdentityKey { get; set; }
    public ManagementRole Role { get; set; } = ManagementRole.User;
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
