using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Security;

public sealed class LocalTokenService
{
    public const string Issuer = "shuai-tunnel";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly AuthOptions _options;
    private readonly byte[] _key;

    public LocalTokenService(IOptions<AuthOptions> options)
    {
        _options = options.Value;
        _key = BuildKey(_options.JwtSecret);
    }

    public long TtlSeconds => Math.Max(60, _options.TokenTtlSeconds);

    public bool IsPasswordLoginEnabled =>
        _options.PasswordLoginEnabled && !string.IsNullOrWhiteSpace(_options.Password);

    public bool Authenticate(string? username, string? password)
    {
        if (!IsPasswordLoginEnabled || username is null || password is null)
        {
            return false;
        }

        return ConstantTimeEquals(_options.Username, username)
            & ConstantTimeEquals(_options.Password, password);
    }

    public TokenResponse IssueTokenBody(string username) => new(
        IssueToken(username, _options.TenantId, ManagementRole.Admin),
        "Bearer",
        TtlSeconds);

    public TokenResponse IssueTokenBody(string username, string tenantId, ManagementRole role) => new(
        IssueToken(username, tenantId, role),
        "Bearer",
        TtlSeconds);

    public string IssueToken(string username) => IssueToken(username, _options.TenantId, ManagementRole.Admin);

    public string IssueToken(string username, string tenantId, ManagementRole role)
    {
        var now = DateTimeOffset.UtcNow;
        var header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = "HS256",
            typ = "JWT",
        }, JsonOptions));
        var payload = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            iss = Issuer,
            sub = username,
            tenant_id = NormalizeTenant(tenantId),
            role = RoleWire(role),
            iat = now.ToUnixTimeSeconds(),
            exp = now.AddSeconds(TtlSeconds).ToUnixTimeSeconds(),
        }, JsonOptions));
        var signingInput = $"{header}.{payload}";
        var signature = Base64UrlEncode(HMACSHA256.HashData(_key, Encoding.ASCII.GetBytes(signingInput)));
        return $"{signingInput}.{signature}";
    }

    public string RegistrationCodeHash(string registrationId, string code)
    {
        var input = Encoding.UTF8.GetBytes($"{registrationId}:{code}");
        return Convert.ToHexString(HMACSHA256.HashData(_key, input)).ToLowerInvariant();
    }

    public ClaimsPrincipal? Validate(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        var signingInput = $"{parts[0]}.{parts[1]}";
        var expectedSignature = HMACSHA256.HashData(_key, Encoding.ASCII.GetBytes(signingInput));
        byte[] actualSignature;
        try
        {
            actualSignature = Base64UrlDecode(parts[2]);
        }
        catch (FormatException)
        {
            return null;
        }
        if (actualSignature.Length != expectedSignature.Length
            || !CryptographicOperations.FixedTimeEquals(actualSignature, expectedSignature))
        {
            return null;
        }

        try
        {
            using var header = JsonDocument.Parse(Base64UrlDecode(parts[0]));
            if (header.RootElement.GetProperty("alg").GetString() != "HS256")
            {
                return null;
            }

            using var payload = JsonDocument.Parse(Base64UrlDecode(parts[1]));
            if (payload.RootElement.GetProperty("iss").GetString() != Issuer)
            {
                return null;
            }
            var subject = payload.RootElement.GetProperty("sub").GetString();
            if (string.IsNullOrWhiteSpace(subject))
            {
                return null;
            }
            var tenantId = TryGetString(payload.RootElement, "tenant_id") ?? _options.TenantId;
            var role = ParseRole(TryGetString(payload.RootElement, "role"));
            if (role == ManagementRole.User
                && string.Equals(subject, _options.Username, StringComparison.OrdinalIgnoreCase))
            {
                role = ManagementRole.Admin;
            }
            var exp = payload.RootElement.GetProperty("exp").GetInt64();
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= exp)
            {
                return null;
            }

            var identity = new ClaimsIdentity("LocalBearer");
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, subject));
            identity.AddClaim(new Claim(ClaimTypes.Name, subject));
            identity.AddClaim(new Claim("iss", Issuer));
            identity.AddClaim(new Claim("tenant_id", NormalizeTenant(tenantId)));
            identity.AddClaim(new Claim(ClaimTypes.Role, RoleWire(role)));
            identity.AddClaim(new Claim("role", RoleWire(role)));
            return new ClaimsPrincipal(identity);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException
            or FormatException)
        {
            return null;
        }
    }

    private static bool ConstantTimeEquals(string expected, string actual)
    {
        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expected ?? string.Empty));
        var actualHash = SHA256.HashData(Encoding.UTF8.GetBytes(actual ?? string.Empty));
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }

    private static byte[] BuildKey(string? secret)
    {
        if (!string.IsNullOrWhiteSpace(secret))
        {
            return SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        }

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + ((4 - padded.Length % 4) % 4), '=');
        return Convert.FromBase64String(padded);
    }

    private static string NormalizeTenant(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "default" : value.Trim();

    private static string RoleWire(ManagementRole role) => role == ManagementRole.Admin ? "ADMIN" : "USER";

    private static ManagementRole ParseRole(string? value) =>
        string.Equals(value, "ADMIN", StringComparison.OrdinalIgnoreCase)
            ? ManagementRole.Admin
            : ManagementRole.User;

    private static string? TryGetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? value.GetString() : null;
}

public sealed record TokenResponse(string AccessToken, string TokenType, long ExpiresIn);
