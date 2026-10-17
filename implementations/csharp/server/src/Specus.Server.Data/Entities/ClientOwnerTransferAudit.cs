namespace Specus.Server.Data.Entities;

// Durable ownership journal. No credential secrets, runtime tokens or machine identifiers.
public sealed class ClientOwnerTransferAudit
{
    public long Id { get; set; }
    public string TenantId { get; set; } = string.Empty;
    public DateTimeOffset OccurredAt { get; set; }
    public string Actor { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public long PathId { get; set; }
    public string TargetUsername { get; set; } = string.Empty;
    public long? CredentialId { get; set; }
    public string DetailJson { get; set; } = string.Empty;
}
