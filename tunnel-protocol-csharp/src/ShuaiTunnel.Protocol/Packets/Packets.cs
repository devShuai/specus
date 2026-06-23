namespace ShuaiTunnel.Protocol.Packets;

public sealed class LoginRequestPacket : Packet
{
    public override sbyte Command => Protocol.Command.LoginRequest;

    public string? ClientName { get; set; }
    public long? ClientSessionId { get; set; }
    public string? AccessToken { get; set; }
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

public sealed class HttpRequestPacket : Packet
{
    public override sbyte Command => Protocol.Command.HttpRequest;

    public string? ClientName { get; set; }
    public string? ToClientName { get; set; }
    public string? RequestId { get; set; }
    public string? RequestMethod { get; set; }
    public string? RequestUrl { get; set; }
    public Dictionary<string, string>? HeaderMap { get; set; }
    public Dictionary<string, string>? ParamMap { get; set; }
    public string? Body { get; set; }
}

public sealed class HttpResponsePacket : Packet
{
    public override sbyte Command => Protocol.Command.HttpResponse;

    public string? ClientName { get; set; }
    public string? ToClientName { get; set; }
    public string? RequestId { get; set; }
    public string? Response { get; set; }
}

public sealed class DirectHttpRequestPacket : Packet
{
    public override sbyte Command => Protocol.Command.DirectHttpRequest;

    public string? RequestId { get; set; }
    public string? RequestMethod { get; set; }
    public string? Route { get; set; }
    public string? RelativePath { get; set; }
    public string? RawQuery { get; set; }
    public List<string>? Headers { get; set; }
    public byte[]? Body { get; set; }
}

public sealed class DirectHttpResponsePacket : Packet
{
    public override sbyte Command => Protocol.Command.DirectHttpResponse;

    public string? RequestId { get; set; }
    public int StatusCode { get; set; }
    public List<string>? Headers { get; set; }
    public byte[]? Body { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// NAT_MESSAGE has a custom body layout that bypasses the per-class compact-binary schema:
/// <c>int32 type | int32 metaLen | utf8 fastjson meta | optional compact-binary payload bytes</c>.
/// </summary>
public sealed class NatMessagePacket : Packet
{
    public override sbyte Command => Protocol.Command.NatMessage;

    public NatMessageType NatMessageType { get; set; }

    /// <summary>
    /// JSON metadata. <see cref="object"/> values mirror Java's <c>Map&lt;String, Object&gt;</c>:
    /// the Jackson/FastJson roundtrip will produce <see cref="string"/>, boxed numerics, etc.
    /// On the C# side we deserialize from JSON via <see cref="System.Text.Json"/>.
    /// </summary>
    public Dictionary<string, object?>? MetaData { get; set; }

    public byte[]? Data { get; set; }
}
