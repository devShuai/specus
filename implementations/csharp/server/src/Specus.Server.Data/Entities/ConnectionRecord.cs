namespace Specus.Server.Data.Entities;

/// <summary>
/// Mirrors <c>specus_connection_record</c> — the audit row for a control-channel login attempt.
/// <see cref="Id"/> is autoincrement (matches Java's <c>GenerationType.IDENTITY</c>).
/// <see cref="DisconnectedAt"/> stays null while the connection is live; on close
/// (or graceful shutdown) the disconnect handler stamps both <see cref="DisconnectedAt"/>
/// and <see cref="DisconnectReason"/>.
/// </summary>
public sealed class ConnectionRecord
{
    public long Id { get; set; }
    public string? TenantId { get; set; } = "default";
    public long? ClientId { get; set; }
    public string ClientName { get; set; } = string.Empty;
    public string? ChannelId { get; set; }
    public string? RemoteAddress { get; set; }
    public DateTimeOffset ConnectedAt { get; set; }
    public DateTimeOffset? DisconnectedAt { get; set; }
    public bool Success { get; set; }
    public string? FailureReason { get; set; }

    /// <summary>
    /// Stored as the Java enum <c>name()</c> wire string (e.g. <c>"LOGIN_FAILURE"</c>) so the SPA
    /// reads the same column the Java server wrote. Use <see cref="DisconnectReasonExtensions.Parse"/>
    /// to lift back to the C# enum.
    /// </summary>
    public string? DisconnectReason { get; set; }
}
