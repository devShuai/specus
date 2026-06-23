using System.Security.Cryptography;
using System.Text;

namespace ShuaiTunnel.Protocol.Security;

/// <summary>
/// Mirrors the Java client startup API-key signature flow:
/// <code>
/// key  = SHA-256(secret) // 32 raw bytes
/// msg  = apiKey + "\n" + timestamp + "\n" + nonce + "\n" + machineFingerprint + "\n" + osUser
/// sign = hex(HMAC-SHA256(key, msg))
/// </code>
/// </summary>
public static class HmacSigner
{
    public const int SignatureLength = 32;
    private const char Delimiter = '\n';

    public static byte[] Sha256(string input)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }
        return SHA256.HashData(Encoding.UTF8.GetBytes(input));
    }

    public static byte[] HmacSha256(byte[] key, string message)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }
        if (message is null)
        {
            throw new ArgumentNullException(nameof(message));
        }
        return HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(message));
    }

    public static string SignClientStartup(
        string? apiKey,
        string? timestamp,
        string? nonce,
        string? machineFingerprint,
        string? osUser,
        byte[] key)
    {
        var msg = string.Join(Delimiter,
            apiKey ?? "",
            timestamp ?? "",
            nonce ?? "",
            machineFingerprint ?? "",
            osUser ?? "");
        return Convert.ToHexString(HmacSha256(key, msg)).ToLowerInvariant();
    }

    public static byte[] DecodeHex(string hex)
    {
        if (hex is null || (hex.Length & 1) != 0)
        {
            throw new ArgumentException("hex string must be non-null and even length", nameof(hex));
        }
        return Convert.FromHexString(hex);
    }
}
