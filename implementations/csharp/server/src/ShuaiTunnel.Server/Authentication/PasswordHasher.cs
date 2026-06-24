using System.Security.Cryptography;
using System.Text;

namespace ShuaiTunnel.Server.Authentication;

/// <summary>
/// Mirrors <c>com.theshuai.tunnelserver.security.PasswordService</c>: the stored hash is
/// hex(SHA-256(plaintext)), no salt. The HMAC login flow needs the 32 raw bytes of the digest
/// as the HMAC key, so the format must stay byte-identical to Java's.
///
/// <para>Generated passwords come out of an 18-char alphabet of unambiguous letters and digits.
/// Confusables ('0', '1', 'I', 'O', 'l') are excluded so admins can read them aloud.</para>
/// </summary>
public static class PasswordHasher
{
    private const string PasswordAlphabet =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    public static string GeneratePassword()
    {
        Span<char> buffer = stackalloc char[18];
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] = PasswordAlphabet[RandomNumberGenerator.GetInt32(0, PasswordAlphabet.Length)];
        }
        return new string(buffer);
    }

    public static string Hash(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("password cannot be blank", nameof(password));
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
    }

    public static bool Matches(string password, string expectedHexHash)
    {
        if (password is null || expectedHexHash is null || expectedHexHash.Length != 64)
        {
            return false;
        }
        Span<byte> actual = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(password), actual);

        byte[] expected;
        try
        {
            expected = Convert.FromHexString(expectedHexHash);
        }
        catch (FormatException)
        {
            return false;
        }
        if (expected.Length != 32)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
