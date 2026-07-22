namespace ShuaiTunnel.Protocol.Packets;

public sealed class LoginRequestPacket : Packet
{
    public override sbyte Command => Protocol.Command.LoginRequest;

    public string? ClientName { get; set; }
    public long? ClientSessionId { get; set; }
    public string? AccessToken { get; set; }
    public string? ConnectionRole { get; set; }
}

public sealed class LoginResponsePacket : Packet
{
    public override sbyte Command => Protocol.Command.LoginResponse;

    public string? ClientName { get; set; }
    public bool Success { get; set; }
    public string? Reason { get; set; }
}

public sealed class LogoutRequestPacket : Packet
{
    public override sbyte Command => Protocol.Command.LogoutRequest;
}

public sealed class LogoutResponsePacket : Packet
{
    public override sbyte Command => Protocol.Command.LogoutResponse;

    public bool Success { get; set; }
    public string? Reason { get; set; }
}

public sealed class HeartbeatRequestPacket : Packet
{
    public override sbyte Command => Protocol.Command.HeartbeatRequest;
}

public sealed class HeartbeatResponsePacket : Packet
{
    public override sbyte Command => Protocol.Command.HeartbeatResponse;
}

public sealed class MessageRequestPacket : Packet
{
    public override sbyte Command => Protocol.Command.MessageRequest;

    public string? ClientName { get; set; }
    public string? ToClientName { get; set; }
    public MessageType? MessageType { get; set; }
    public string? Message { get; set; }
}

public sealed class MessageResponsePacket : Packet
{
    public override sbyte Command => Protocol.Command.MessageResponse;

    public string? ClientName { get; set; }
    public string? ToClientName { get; set; }
    public MessageType? MessageType { get; set; }
    public string? Message { get; set; }
}

/// <summary>
/// NAT_MESSAGE v2 has a custom body layout:
/// <c>type(u8) | flags(u8) | metadataLength(u16) | streamId(u32) | value(u32) |
/// dataLength(u32) | metadata | raw data</c>.
/// </summary>
public sealed class NatMessagePacket : Packet
{
    public const byte FlagEndStream = 0x01;

    public override sbyte Command => Protocol.Command.NatMessage;

    public NatMessageType NatMessageType { get; set; }

    public byte Flags { get; set; }

    public uint StreamId { get; set; }

    public uint Value { get; set; }

    /// <summary>
    /// JSON metadata. <see cref="object"/> values mirror Java's <c>Map&lt;String, Object&gt;</c>:
    /// the Jackson/FastJson roundtrip will produce <see cref="string"/>, boxed numerics, etc.
    /// On the C# side we deserialize from JSON via <see cref="System.Text.Json"/>.
    /// </summary>
    public Dictionary<string, object?>? MetaData { get; set; }

    public byte[]? Data { get; set; }
}
