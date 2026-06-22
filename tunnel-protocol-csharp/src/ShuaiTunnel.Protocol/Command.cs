namespace ShuaiTunnel.Protocol;

public static class Command
{
    public const sbyte LoginRequest = 1;
    public const sbyte LoginResponse = -1;
    public const sbyte MessageRequest = 2;
    public const sbyte MessageResponse = -2;
    public const sbyte LogoutRequest = 3;
    public const sbyte LogoutResponse = -3;
    public const sbyte HeartbeatRequest = 4;
    public const sbyte HeartbeatResponse = -4;
    public const sbyte HttpRequest = 5;
    public const sbyte HttpResponse = -5;
    public const sbyte NatMessage = 6;
    public const sbyte DirectHttpRequest = 7;
    public const sbyte DirectHttpResponse = -7;
}

public static class SerializerAlgorithm
{
    public const byte FastJson = 1;
    public const byte Jackson = 2;
    public const byte Xml = 3;
    public const byte CompactBinary = 4;
    public const byte Protobuf = 5;
}
