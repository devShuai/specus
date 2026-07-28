namespace Specus.Protocol;

/// <summary>
/// Stable control-protocol wire IDs. Values must never be inferred from declaration order.
/// </summary>
public enum MessageType
{
    ServerToClient = 1,
    ClientToServer = 2,
    ClientToClient = 3,
    NatControl = 4,
    PeerControl = 5,
}

/// <summary>
/// Mirrors <c>com.theshuai.common.protocol.NatMessageType</c>. Wire format uses the explicit
/// <see cref="NatMessageTypeExtensions.Code"/> int (not the C# numeric value) — keep both in sync.
/// </summary>
public enum NatMessageType
{
    Register = 1,
    RegisterResult = 2,
    Open = 3,
    Fin = 4,
    Data = 5,
    Keepalive = 6,
    Unregister = 7,
    Rst = 8,
    WindowUpdate = 9,
}

public static class NatMessageTypeExtensions
{
    public static int Code(this NatMessageType type) => (int)type;

    public static NatMessageType? FromCode(int code) =>
        Enum.IsDefined(typeof(NatMessageType), code) ? (NatMessageType)code : null;
}
