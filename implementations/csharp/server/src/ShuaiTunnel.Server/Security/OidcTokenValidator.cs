using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.Security;

public sealed class AdminBearerTokenValidator
{
    private readonly LocalTokenService _localTokens;
    private readonly OidcTokenValidator _oidcTokens;

    public AdminBearerTokenValidator(LocalTokenService localTokens, OidcTokenValidator oidcTokens)
    {
        _localTokens = localTokens;
        _oidcTokens = oidcTokens;
    }

    public ValueTask<ClaimsPrincipal?> ValidateAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return ValueTask.FromResult<ClaimsPrincipal?>(null);
        }

        var algorithm = JwtTokenUtility.ReadAlgorithm(token);
        if (algorithm.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
        {
            return ValueTask.FromResult(_localTokens.Validate(token));
        }

        return _oidcTokens.ValidateAsync(token, cancellationToken);
    }

}

public sealed class OidcTokenValidator
{
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan KeyCacheTtl = TimeSpan.FromMinutes(5);

    private readonly OidcOptions _options;
    private readonly IOidcJwkProvider _jwkProvider;
    private readonly ILogger<OidcTokenValidator> _logger;
    private readonly SemaphoreSlim _keyLock = new(1, 1);

    private IReadOnlyList<RsaJwk> _cachedKeys = [];
    private DateTimeOffset _keysExpiresAt;

    public OidcTokenValidator(IOptions<OidcOptions> options,
        IOidcJwkProvider jwkProvider,
        ILogger<OidcTokenValidator> logger)
    {
        _options = options.Value;
        _jwkProvider = jwkProvider;
        _logger = logger;
    }

    public async ValueTask<ClaimsPrincipal?> ValidateAsync(string token,
        CancellationToken cancellationToken = default)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        TokenHeader header;
        TokenPayload payload;
        byte[] signature;
        try
        {
            header = ReadHeader(parts[0]);
            if (!header.Algorithm.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            payload = ReadPayload(parts[1]);
            signature = JwtTokenUtility.Base64UrlDecode(parts[2]);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException)
        {
            return null;
        }

        if (!ValidateClaims(payload))
        {
            return null;
        }

        var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        var key = await FindKeyAsync(header.KeyId, cancellationToken).ConfigureAwait(false);
        if (key is null)
        {
            return null;
        }

        if (!VerifySignature(key, signingInput, signature))
        {
            key = await FindKeyAsync(header.KeyId, cancellationToken, forceRefresh: true).ConfigureAwait(false);
            if (key is null || !VerifySignature(key, signingInput, signature))
            {
                return null;
            }
        }

        var identity = new ClaimsIdentity("OidcBearer");
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, payload.Subject));
        identity.AddClaim(new Claim(ClaimTypes.Name, payload.Name ?? payload.Subject));
        if (!string.IsNullOrWhiteSpace(payload.Issuer))
        {
            identity.AddClaim(new Claim("iss", payload.Issuer));
        }
        if (!string.IsNullOrWhiteSpace(payload.TenantId))
        {
            identity.AddClaim(new Claim("tenant_id", payload.TenantId));
        }
        foreach (var audience in payload.Audiences)
        {
            identity.AddClaim(new Claim("aud", audience));
        }
        return new ClaimsPrincipal(identity);
    }

    private bool ValidateClaims(TokenPayload payload)
    {
        var now = DateTimeOffset.UtcNow;
        if (string.IsNullOrWhiteSpace(payload.Subject))
        {
            return false;
        }

        if (payload.ExpiresAt is null || now - ClockSkew >= payload.ExpiresAt.Value)
        {
            return false;
        }

        if (payload.NotBefore is not null && now + ClockSkew < payload.NotBefore.Value)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(_options.Issuer)
            && !string.Equals(payload.Issuer, _options.Issuer, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(_options.Audience)
            && !payload.Audiences.Contains(_options.Audience, StringComparer.Ordinal))
        {
            return false;
        }

        return true;
    }

    private async Task<RsaJwk?> FindKeyAsync(string? keyId, CancellationToken cancellationToken,
        bool forceRefresh = false)
    {
        var keys = await GetKeysAsync(forceRefresh, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(keyId))
        {
            return keys.FirstOrDefault(key => string.Equals(key.KeyId, keyId, StringComparison.Ordinal));
        }

        return keys.Count == 1 ? keys[0] : null;
    }

    private async Task<IReadOnlyList<RsaJwk>> GetKeysAsync(bool forceRefresh, CancellationToken cancellationToken)
    {
        if (!forceRefresh && _cachedKeys.Count > 0 && DateTimeOffset.UtcNow < _keysExpiresAt)
        {
            return _cachedKeys;
        }

        await _keyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!forceRefresh && _cachedKeys.Count > 0 && DateTimeOffset.UtcNow < _keysExpiresAt)
            {
                return _cachedKeys;
            }

            var jwksUri = new Uri(_options.JwkSetUri, UriKind.Absolute);
            var body = await _jwkProvider.GetJwksAsync(jwksUri, cancellationToken).ConfigureAwait(false);
            _cachedKeys = ParseJwks(body);
            _keysExpiresAt = DateTimeOffset.UtcNow.Add(KeyCacheTtl);
            return _cachedKeys;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or UriFormatException
            or FormatException or InvalidOperationException)
        {
            _logger.LogWarning(ex, "[oidc] failed to refresh JWKS");
            _cachedKeys = [];
            _keysExpiresAt = DateTimeOffset.MinValue;
            return _cachedKeys;
        }
        finally
        {
            _keyLock.Release();
        }
    }

    private static bool VerifySignature(RsaJwk key, byte[] signingInput, byte[] signature)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = key.Modulus,
            Exponent = key.Exponent,
        });
        return rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
    }

    private static TokenHeader ReadHeader(string encoded)
    {
        using var document = JsonDocument.Parse(JwtTokenUtility.Base64UrlDecode(encoded));
        var root = document.RootElement;
        return new TokenHeader(
            root.TryGetProperty("alg", out var alg) ? alg.GetString() ?? string.Empty : string.Empty,
            root.TryGetProperty("kid", out var kid) ? kid.GetString() : null);
    }

    private TokenPayload ReadPayload(string encoded)
    {
        using var document = JsonDocument.Parse(JwtTokenUtility.Base64UrlDecode(encoded));
        var root = document.RootElement;
        var subject = ReadClaimAsString(root, "sub") ?? string.Empty;
        var name = ReadClaimAsString(root, "preferred_username")
            ?? ReadClaimAsString(root, "name")
            ?? subject;
        return new TokenPayload(
            ReadClaimAsString(root, "iss"),
            subject,
            name,
            ReadAudiences(root),
            ReadUnixTime(root, "exp"),
            ReadUnixTime(root, "nbf"),
            ReadClaimAsString(root, TenantClaimName(_options.TenantClaim)));
    }

    private static IReadOnlyList<RsaJwk> ParseJwks(string body)
    {
        using var document = JsonDocument.Parse(body);
        if (!document.RootElement.TryGetProperty("keys", out var keysElement)
            || keysElement.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var keys = new List<RsaJwk>();
        foreach (var key in keysElement.EnumerateArray())
        {
            var kty = ReadString(key, "kty");
            var n = ReadString(key, "n");
            var e = ReadString(key, "e");
            if (!string.Equals(kty, "RSA", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(n)
                || string.IsNullOrWhiteSpace(e))
            {
                continue;
            }

            var alg = ReadString(key, "alg");
            if (!string.IsNullOrWhiteSpace(alg)
                && !alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            keys.Add(new RsaJwk(
                ReadString(key, "kid"),
                JwtTokenUtility.Base64UrlDecode(n),
                JwtTokenUtility.Base64UrlDecode(e)));
        }

        return keys;
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static string TenantClaimName(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "tenant_id" : value.Trim();

    private static string? ReadClaimAsString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property))
        {
            return null;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String => string.IsNullOrWhiteSpace(property.GetString())
                ? null
                : property.GetString()!.Trim(),
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => property.GetRawText(),
            _ => null,
        };
    }

    private static IReadOnlyList<string> ReadAudiences(JsonElement root)
    {
        if (!root.TryGetProperty("aud", out var aud))
        {
            return [];
        }

        if (aud.ValueKind == JsonValueKind.String)
        {
            var value = aud.GetString();
            return string.IsNullOrWhiteSpace(value) ? [] : [value];
        }

        if (aud.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var audiences = new List<string>();
        foreach (var item in aud.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(item.GetString()))
            {
                audiences.Add(item.GetString()!);
            }
        }
        return audiences;
    }

    private static DateTimeOffset? ReadUnixTime(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var property) || !property.TryGetInt64(out var seconds))
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private sealed record TokenHeader(string Algorithm, string? KeyId);

    private sealed record TokenPayload(
        string? Issuer,
        string Subject,
        string? Name,
        IReadOnlyList<string> Audiences,
        DateTimeOffset? ExpiresAt,
        DateTimeOffset? NotBefore,
        string? TenantId);

    private sealed record RsaJwk(string? KeyId, byte[] Modulus, byte[] Exponent);
}

public interface IOidcJwkProvider
{
    Task<string> GetJwksAsync(Uri jwksUri, CancellationToken cancellationToken = default);
}

public sealed class HttpOidcJwkProvider : IOidcJwkProvider
{
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(15),
    };

    public Task<string> GetJwksAsync(Uri jwksUri, CancellationToken cancellationToken = default) =>
        HttpClient.GetStringAsync(jwksUri, cancellationToken);
}

internal static class JwtTokenUtility
{
    public static string ReadAlgorithm(string token)
    {
        var dot = token.IndexOf('.', StringComparison.Ordinal);
        if (dot <= 0)
        {
            return string.Empty;
        }

        try
        {
            using var document = JsonDocument.Parse(Base64UrlDecode(token[..dot]));
            return document.RootElement.TryGetProperty("alg", out var alg)
                ? alg.GetString() ?? string.Empty
                : string.Empty;
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return string.Empty;
        }
    }

    public static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + ((4 - padded.Length % 4) % 4), '=');
        return Convert.FromBase64String(padded);
    }
}
