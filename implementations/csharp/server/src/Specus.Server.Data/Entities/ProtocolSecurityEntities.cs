namespace Specus.Server.Data.Entities;

public sealed class ClientAuthNonce
{
    public string ApiKeyHash { get; set; } = string.Empty;
    public string NonceHash { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class WebSocketTicket
{
    public string TokenHash { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string? TenantId { get; set; }
    public bool IsAdmin { get; set; }
    public string? RoomId { get; set; }
    public string? RoomKey { get; set; }
    public string? PeerId { get; set; }
    public string? DisplayName { get; set; }
    public bool SharedRoom { get; set; }
    public string RemoteAddressHash { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
