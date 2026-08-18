using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Specus.Server.Authentication;

/// <summary>
/// Password and secret hashing, mirroring <c>com.theshuai.specusserver.security.PasswordService</c>
/// and the Go <c>internal/auth</c> package byte for byte.
///
/// <para>Human passwords use a salted, iterated KDF in a self-describing format shared by every
/// implementation: <c>$pbkdf2-sha256$v=1$i=&lt;iterations&gt;$&lt;base64 salt&gt;$&lt;base64 key&gt;</c>.
/// Unsalted single-round SHA-256, which this replaces, hands an attacker who reads the database the
/// whole password list at rainbow-table speed. The parameters travel with each hash, so the cost can
/// be raised later without invalidating stored credentials.</para>
///
/// <para>High-entropy secrets keep the plain digest via <see cref="HashToken"/>. That is not a
/// weaker choice for them but a required one: the HMAC client-login flow uses the 32 raw bytes of
/// the credential digest as its HMAC key, so that format must stay byte-identical across
/// implementations. Per-route gate secrets also stay digests because they are checked on every
/// proxied request, where an iterated KDF would be a self-inflicted denial of service.</para>
///
/// <para>Generated passwords come out of an 18-char alphabet of unambiguous letters and digits.
/// Confusables ('0', '1', 'I', 'O', 'l') are excluded so admins can read them aloud.</para>
/// </summary>
public static class PasswordHasher
{
    private const string PasswordAlphabet =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    internal const string Algorithm = "pbkdf2-sha256";
    internal const int Version = 1;

    /// <summary>Cost applied to new and upgraded hashes.</summary>
    public const int DefaultIterations = 210_000;

    /// <summary>Stored hashes claiming a lower cost are treated as corrupt rather than trusted.</summary>
    public const int MinIterations = 1_000;

    private const int SaltBytes = 16;
    private const int KeyBytes = 32;
    private const int LegacyHexLength = 64;

    public static string GeneratePassword()
    {
        Span<char> buffer = stackalloc char[18];
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] = PasswordAlphabet[RandomNumberGenerator.GetInt32(0, PasswordAlphabet.Length)];
        }
        return new string(buffer);
    }

    /// <summary>Derives a new salted hash for a human password at the current cost.</summary>
    public static string Hash(string password) => Hash(password, DefaultIterations);

    internal static string Hash(string password, int iterations)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("password cannot be blank", nameof(password));
        }
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var derived = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, KeyBytes);
        return string.Create(CultureInfo.InvariantCulture,
            $"${Algorithm}$v={Version}$i={iterations}${Base64Raw(salt)}${Base64Raw(derived)}");
    }

    /// <summary>
    /// Hashes a high-entropy secret. Deterministic, because these values double as lookup keys and
    /// as HMAC key material.
    /// </summary>
    public static string HashToken(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();
    }

    /// <summary>Derives a deterministic lookup key from non-secret identifiers. An index, not a credential.</summary>
    public static string DigestKey(string value) => HashToken(value);

    /// <summary>Verifies a token or index digest. Never accepts a password-format hash.</summary>
    public static bool TokenMatches(string secret, string expectedHexHash)
    {
        if (secret is null || expectedHexHash is null || expectedHexHash.Length != LegacyHexLength)
        {
            return false;
        }
        Span<byte> actual = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(secret), actual);

        byte[] expected;
        try
        {
            expected = Convert.FromHexString(expectedHexHash);
        }
        catch (FormatException)
        {
            return false;
        }
        return expected.Length == 32 && CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>Verifies without reporting whether the stored hash should be replaced.</summary>
    public static bool Matches(string password, string expectedHash)
        => Verify(password, expectedHash).Matches;

    /// <summary>
    /// Outcome of verifying a password. <paramref name="NeedsUpgrade"/> is how legacy and
    /// under-cost hashes get retired: a successful login is the only moment the plaintext exists.
    /// </summary>
    public readonly record struct Verification(
        bool Matches, bool NeedsUpgrade, string? UpgradedHash, bool StoredIsLegacy)
    {
        internal static Verification Failed(bool legacy) => new(false, false, null, legacy);
    }

    /// <summary>Verifies against either the current format or a legacy SHA-256 hash.</summary>
    public static Verification Verify(string password, string expectedHash)
    {
        if (password is null || expectedHash is null)
        {
            return Verification.Failed(false);
        }
        var stored = expectedHash.Trim();
        if (stored.Length == 0)
        {
            return Verification.Failed(false);
        }
        if (!stored.StartsWith('$'))
        {
            return TokenMatches(password, stored)
                ? new Verification(true, true, Hash(password), true)
                : Verification.Failed(true);
        }

        if (!TryParse(stored, out var iterations, out var salt, out var key))
        {
            return Verification.Failed(false);
        }
        var derived = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, key.Length);
        if (!CryptographicOperations.FixedTimeEquals(derived, key))
        {
            return Verification.Failed(false);
        }
        return iterations < DefaultIterations
            ? new Verification(true, true, Hash(password), false)
            : new Verification(true, false, null, false);
    }

    /// <summary>Whether the stored value predates the salted format and still needs a login to migrate.</summary>
    public static bool IsLegacyHash(string? storedHash)
        => !string.IsNullOrWhiteSpace(storedHash) && !storedHash.Trim().StartsWith('$');

    private static bool TryParse(string stored, out int iterations, out byte[] salt, out byte[] key)
    {
        iterations = 0;
        salt = [];
        key = [];

        // A leading '$' makes the first field empty: "", algorithm, version, iterations, salt, key.
        var parts = stored.Split('$');
        if (parts.Length != 6 || parts[0].Length != 0 || parts[1] != Algorithm)
        {
            return false;
        }
        if (!TryParseTagged(parts[2], "v=", out var version) || version != Version)
        {
            return false;
        }
        if (!TryParseTagged(parts[3], "i=", out iterations) || iterations < MinIterations)
        {
            return false;
        }
        return TryDecodeBase64(parts[4], out salt) && salt.Length > 0
               && TryDecodeBase64(parts[5], out key) && key.Length > 0;
    }

    private static bool TryParseTagged(string field, string prefix, out int value)
    {
        value = 0;
        return field.StartsWith(prefix, StringComparison.Ordinal)
               && int.TryParse(field.AsSpan(prefix.Length), NumberStyles.None,
                   CultureInfo.InvariantCulture, out value);
    }

    private static bool TryDecodeBase64(string value, out byte[] decoded)
    {
        // The format stores unpadded base64; restore the padding the decoder requires.
        var padded = value.Length % 4 == 0 ? value : value.PadRight(value.Length + (4 - value.Length % 4), '=');
        var buffer = new byte[padded.Length / 4 * 3];
        if (Convert.TryFromBase64String(padded, buffer, out var written))
        {
            decoded = buffer[..written];
            return true;
        }
        decoded = [];
        return false;
    }

    private static string Base64Raw(byte[] value) => Convert.ToBase64String(value).TrimEnd('=');
}
