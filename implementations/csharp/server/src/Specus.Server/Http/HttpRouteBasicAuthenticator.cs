using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Specus.Server.Authentication;

namespace Specus.Server.Http;

internal static class HttpRouteBasicAuthenticator
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static bool IsAuthorized(string? authorization, string? expectedUsername,
        string? expectedPasswordHash)
    {
        if (string.IsNullOrWhiteSpace(expectedUsername)
            || string.IsNullOrWhiteSpace(expectedPasswordHash)
            || !AuthenticationHeaderValue.TryParse(authorization, out var header)
            || !header.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(header.Parameter))
        {
            return false;
        }

        string decoded;
        try
        {
            decoded = StrictUtf8.GetString(Convert.FromBase64String(header.Parameter));
        }
        catch (Exception exception) when (exception is FormatException or DecoderFallbackException)
        {
            return false;
        }

        var separator = decoded.IndexOf(':', StringComparison.Ordinal);
        if (separator < 0)
        {
            return false;
        }
        var username = decoded[..separator];
        var password = decoded[(separator + 1)..];
        return ConstantTimeEquals(expectedUsername, username)
               & PasswordHasher.Matches(password, expectedPasswordHash);
    }

    private static bool ConstantTimeEquals(string expected, string actual)
    {
        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        var actualHash = SHA256.HashData(Encoding.UTF8.GetBytes(actual));
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }
}
