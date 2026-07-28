namespace Specus.Server.Data.Entities;

/// <summary>
/// Reasons stamped on a control connection's lifecycle row. Mirrors Java's
/// <c>com.theshuai.specusserver.management.model.DisconnectReason</c> enum names — these
/// strings travel through both the channel attribute and the persisted column.
/// </summary>
public enum DisconnectReason
{
    LoginFailure,
    ClientClosed,
    IoError,
    IdleTimeout,
    HeartbeatWriteFailed,
    ProtocolViolation,
    RegisterFailed,
    ReplacedByNewLogin,
    AdminDisabled,
    AdminRenamed,
    AdminDeleted,
    ServerBusy,
    ServerShutdown,
    ServerRestarted,
    Unknown,
}

public static class DisconnectReasonExtensions
{
    /// <summary>Java-side wire form of the enum (UPPER_SNAKE_CASE, as <c>name()</c> emits).</summary>
    public static string ToWireString(this DisconnectReason reason) => reason switch
    {
        DisconnectReason.LoginFailure => "LOGIN_FAILURE",
        DisconnectReason.ClientClosed => "CLIENT_CLOSED",
        DisconnectReason.IoError => "IO_ERROR",
        DisconnectReason.IdleTimeout => "IDLE_TIMEOUT",
        DisconnectReason.HeartbeatWriteFailed => "HEARTBEAT_WRITE_FAILED",
        DisconnectReason.ProtocolViolation => "PROTOCOL_VIOLATION",
        DisconnectReason.RegisterFailed => "REGISTER_FAILED",
        DisconnectReason.ReplacedByNewLogin => "REPLACED_BY_NEW_LOGIN",
        DisconnectReason.AdminDisabled => "ADMIN_DISABLED",
        DisconnectReason.AdminRenamed => "ADMIN_RENAMED",
        DisconnectReason.AdminDeleted => "ADMIN_DELETED",
        DisconnectReason.ServerBusy => "SERVER_BUSY",
        DisconnectReason.ServerShutdown => "SERVER_SHUTDOWN",
        DisconnectReason.ServerRestarted => "SERVER_RESTARTED",
        DisconnectReason.Unknown => "UNKNOWN",
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, null),
    };

    public static DisconnectReason? Parse(string? wireValue) => wireValue switch
    {
        null => null,
        "LOGIN_FAILURE" => DisconnectReason.LoginFailure,
        "CLIENT_CLOSED" => DisconnectReason.ClientClosed,
        "IO_ERROR" => DisconnectReason.IoError,
        "IDLE_TIMEOUT" => DisconnectReason.IdleTimeout,
        "HEARTBEAT_WRITE_FAILED" => DisconnectReason.HeartbeatWriteFailed,
        "PROTOCOL_VIOLATION" => DisconnectReason.ProtocolViolation,
        "REGISTER_FAILED" => DisconnectReason.RegisterFailed,
        "REPLACED_BY_NEW_LOGIN" => DisconnectReason.ReplacedByNewLogin,
        "ADMIN_DISABLED" => DisconnectReason.AdminDisabled,
        "ADMIN_RENAMED" => DisconnectReason.AdminRenamed,
        "ADMIN_DELETED" => DisconnectReason.AdminDeleted,
        "SERVER_BUSY" => DisconnectReason.ServerBusy,
        "SERVER_SHUTDOWN" => DisconnectReason.ServerShutdown,
        "SERVER_RESTARTED" => DisconnectReason.ServerRestarted,
        "UNKNOWN" => DisconnectReason.Unknown,
        _ => DisconnectReason.Unknown,
    };
}
