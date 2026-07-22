namespace ShuaiTunnel.Protocol;

public static class ConnectionRole
{
    public const string Control = "control";
    public const string Data = "data";

    public static bool IsValid(string? value) => value is Control or Data;
}
