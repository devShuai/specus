namespace Specus.Server.Data.Entities;

// Per-process incarnation acknowledgement, never a global audit-ID/time watermark.
public sealed class ClientOwnerTransferReceipt
{
    public string Id { get; set; } = string.Empty;
    public string NodeId { get; set; } = string.Empty;
    public long EventId { get; set; }
    public DateTimeOffset ProcessedAt { get; set; }
}
