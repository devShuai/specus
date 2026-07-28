namespace Specus.Server.Data.Entities;

public sealed class TransferAttachmentDownloadGrant
{
    public long Id { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public string TenantId { get; set; } = "default";
    public string Username { get; set; } = string.Empty;
    public long AttachmentId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}
