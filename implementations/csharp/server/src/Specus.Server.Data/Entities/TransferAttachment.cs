namespace Specus.Server.Data.Entities;

public sealed class TransferAttachment
{
    public long Id { get; set; }
    public string? TenantId { get; set; }
    public string Scope { get; set; } = string.Empty;
    public string? RoomId { get; set; }
    public string? RoomTokenHash { get; set; }
    public string? OwnerUsername { get; set; }
    public long? TargetClientId { get; set; }
    public string ObjectKey { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string MimeType { get; set; } = "application/octet-stream";
    public long SizeBytes { get; set; }
    public string? Sha256 { get; set; }
    public string Status { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset UploadExpiresAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UploadedAt { get; set; }
}
