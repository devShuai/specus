namespace Specus.Server.Data.Entities;

public sealed class UserDiagramDocument
{
    public long Id { get; set; }
    public string TenantId { get; set; } = string.Empty;
    public string OwnerUsername { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public byte[] SnapshotData { get; set; } = [];
    public long SizeBytes { get; set; }
    public long Revision { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class PublicTransferRoom
{
    public long Id { get; set; }
    public string RoomName { get; set; } = string.Empty;
    public string OwnerTokenHash { get; set; } = string.Empty;
    public string CreatedByPeerId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class PublicTransferRoomAccess
{
    public long Id { get; set; }
    public long RoomId { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

public sealed class PublicTransferRoomPairingCode
{
    public long Id { get; set; }
    public long RoomId { get; set; }
    public string CodeHash { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public int MaxUses { get; set; }
    public int UsedCount { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

public sealed class PublicTransferDiagramVersion
{
    public long Id { get; set; }
    public long RoomId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string AuthorPeerId { get; set; } = string.Empty;
    public byte[] SnapshotData { get; set; } = [];
    public long SizeBytes { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
