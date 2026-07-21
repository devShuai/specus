namespace ShuaiTunnel.Server.Data.Entities;

public sealed class ManagementUserEmail
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public DateTimeOffset VerifiedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class ManagementRegistrationChallenge
{
    public string RegistrationId { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string CodeHash { get; set; } = string.Empty;
    public int AttemptsRemaining { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset ResendAvailableAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
