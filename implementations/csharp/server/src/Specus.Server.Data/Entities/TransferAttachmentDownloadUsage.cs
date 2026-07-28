namespace Specus.Server.Data.Entities;

public sealed class TransferAttachmentDownloadUsage
{
    public long Id { get; set; }
    public string TenantId { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public long AttachmentId { get; set; }
    public long SizeBytes { get; set; }
    public string UsageMonth { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
}
