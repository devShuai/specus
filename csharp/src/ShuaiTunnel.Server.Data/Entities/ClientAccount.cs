namespace ShuaiTunnel.Server.Data.Entities;

/// <summary>
/// Mirrors <c>tunnel_client_account</c> in the Java schema. <see cref="Id"/> is application-assigned
/// (NOT auto-increment) — we use a JS-safe random in [1, 2^53-1] so the JSON UI can round-trip
/// the value as a Number. Login HMAC uses <see cref="PasswordHash"/> as hex(SHA-256(plaintext)),
/// decoded back to 32 raw bytes for HMAC-SHA256.
/// </summary>
public sealed class ClientAccount
{
    public long Id { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public int ConnectionRateLimitPerMinute { get; set; } = 30;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
