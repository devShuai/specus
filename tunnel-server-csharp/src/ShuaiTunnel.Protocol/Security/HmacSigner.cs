using System.Security.Cryptography;
using System.Text;

namespace ShuaiTunnel.Protocol.Security;

/// <summary>
/// Mirrors <c>com.theshuai.common.security.HmacSigner</c>. The login flow:
/// <code>
/// key  = SHA-256(password)              // 32 raw bytes
/// msg  = clientName + "\n" + timestamp + "\n" + nonce
/// sign = HMAC-SHA256(key, msg)          // 32 raw bytes
/// </code>
/// The plaintext password never crosses the wire — server stores hex(SHA-256(password))
/// and decodes the hex back to 32 raw bytes when verifying.
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

    public static string SignMessage(string clientName, string timestamp, string nonce, byte[] key)
    {
        var msg = $"{clientName}{Delimiter}{timestamp}{Delimiter}{nonce}";
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
