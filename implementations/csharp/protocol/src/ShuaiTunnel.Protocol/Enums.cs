namespace ShuaiTunnel.Protocol;

/// <summary>
/// Mirrors <c>com.theshuai.common.protocol.MessageType</c>. Order MUST match Java's enum
/// declaration — the compact-binary codec writes <c>ordinal + 1</c> as a varint.
/// </summary>
public enum MessageType
{
    ServerToClient = 0,
    ClientToServer = 1,
    ClientToClient = 2,
    NatControl = 3,
    PeerControl = 4,
}

/// <summary>
/// Mirrors <c>com.theshuai.common.protocol.NatMessageType</c>. Wire format uses the explicit
/// <see cref="NatMessageTypeExtensions.Code"/> int (not the C# numeric value) — keep both in sync.
/// </summary>
public enum NatMessageType
{
    Register = 1,
    RegisterResult = 2,
    Connected = 3,
    Disconnected = 4,
    Data = 5,
    Keepalive = 6,
    Unregister = 7,
    HttpRoutesReport = 8,
}

public static class NatMessageTypeExtensions
{
    public static int Code(this NatMessageType type) => (int)type;

    public static NatMessageType? FromCode(int code) =>
        Enum.IsDefined(typeof(NatMessageType), code) ? (NatMessageType)code : null;
}
