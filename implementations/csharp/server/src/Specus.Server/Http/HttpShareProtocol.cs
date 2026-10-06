using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Specus.Server.Http;

/// <summary>
/// The fixed parts of temporary HTTP shares (protocol/spec/temporary-http-share.md): token format,
/// path-prefix canonicalisation and scope, cookie handling and the response header rewriting.
/// Every function here mirrors <c>tools/protocol/generate_temporary_share_vectors.py</c> one to
/// one and is replayed against <c>temporary-http-share-v1.json</c>.
/// </summary>
public static partial class HttpShareProtocol
{
    public const string TokenVersion = "hs1";
    public const int ShareIdBytes = 12;
    public const int SecretBytes = 32;
    public const string TokenPattern = @"hs1\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})";
    public const string CookieName = "__Secure-specus_http_share";
    public const int MaxCookieCandidates = 4;
    public const string SharePathRoot = "/http-share/";
    public const string LinkRoot = "/#/http-share/";
    public const int MinExpiresInSeconds = 300;
    public const int MaxExpiresInSeconds = 604_800;
    public const int MaxActiveSharesPerRoute = 20;
    public const int LabelMaxCodePoints = 60;
    public const int PathPrefixMaxBytes = 256;
    public static readonly IReadOnlyList<string> ReadMethods = ["GET", "HEAD"];
    public const int MaxConcurrentPerShare = 64;
    public const int SweepIntervalSeconds = 30;
    public const int SweepIntervalMaxSeconds = 60;
    public const int StreamExpiryTickSeconds = 1;
    public const int StreamRecheckSeconds = 2;
    public const int StreamRecheckMaxSeconds = 5;
    public const int ShareRetentionDays = 30;
    public const int AuditRetentionDays = 180;
    public const long ExchangeIntervalMs = 6_000;
    public const int ExchangeBurst = 10;
    public const long ShareIntervalMs = 50;
    public const int ShareBurst = 200;
    public const int ExchangeMaxBodyBytes = 4096;

    public const string AccessRead = "read";
    public const string AccessFull = "full";

    public const string ReasonRevokedByUser = "revoked-by-user";
    public const string ReasonRouteDisabled = "route-disabled";
    public const string ReasonRouteMadePublic = "route-made-public";
    public const string ReasonRouteDeleted = "route-deleted";
    public const string ReasonClientDisabled = "client-disabled";
    public const string ReasonClientDeleted = "client-deleted";
    public const string ReasonCreatorLostAccess = "creator-lost-access";

    public static readonly IReadOnlyList<string> RevokeReasons =
    [
        ReasonRevokedByUser, ReasonRouteDisabled, ReasonRouteMadePublic, ReasonRouteDeleted,
        ReasonClientDisabled, ReasonClientDeleted, ReasonCreatorLostAccess,
    ];

    public const string ActionShareCreated = "share.created";
    public const string ActionShareRevoked = "share.revoked";
    public const string ActionShareExpired = "share.expired";
    public const string ActionRouteCreated = "route.created";
    public const string ActionRouteExposureChanged = "route.exposure-changed";
    public const string ActionRouteCredentialsChanged = "route.credentials-changed";
    public const string ActionRouteDeleted = "route.deleted";

    public static readonly IReadOnlyList<string> AuditActions =
    [
        ActionShareCreated, ActionShareRevoked, ActionShareExpired, ActionRouteCreated,
        ActionRouteExposureChanged, ActionRouteCredentialsChanged, ActionRouteDeleted,
    ];

    public const string ExposureDisabled = "disabled";
    public const string ExposureProtected = "protected";
    public const string ExposurePublic = "public";

    private const string Unreserved =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    // RFC 3986 pchar without ";": a servlet container treats ";" as the start of path parameters,
    // so "/docs/..;/admin" would leave the prefix after the container has normalised it.
    private const string PathChars = Unreserved + "!$&'()*+,=:@/";

    private static readonly HashSet<string> CacheHeaders = new(StringComparer.Ordinal)
    {
        "cache-control", "cdn-cache-control", "surrogate-control", "expires", "pragma",
    };

    [GeneratedRegex(@"\Ahs1\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})\z", RegexOptions.CultureInvariant)]
    private static partial Regex TokenRegex();

    [GeneratedRegex(@"\A[A-Za-z0-9_-]{16}\z", RegexOptions.CultureInvariant)]
    private static partial Regex ShareIdRegex();

    /// <summary>
    /// The share id embedded in a well-formed token, or null. The whole string must match: a
    /// trailing newline or surrounding whitespace is not tolerated.
    /// </summary>
    public static string? ParseToken(string? text)
    {
        if (text is null)
        {
            return null;
        }
        var match = TokenRegex().Match(text);
        return match.Success ? match.Groups[1].Value : null;
    }

    public static bool IsShareId(string? value) => value is not null && ShareIdRegex().IsMatch(value);

    public static string Base64Url(ReadOnlySpan<byte> raw) =>
        Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Builds the share id and token from the raw random bytes (12 and 32 bytes).</summary>
    public static (string ShareId, string Token) MakeToken(ReadOnlySpan<byte> shareIdBytes,
        ReadOnlySpan<byte> secretBytes)
    {
        var shareId = Base64Url(shareIdBytes);
        var secret = Base64Url(secretBytes);
        return (shareId, $"{TokenVersion}.{shareId}.{secret}");
    }

    /// <summary>lowercase_hex(SHA-256(UTF-8(whole token string))).</summary>
    public static string TokenHash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    /// <summary>Compares two lowercase hex digests without an early exit.</summary>
    public static bool HashEquals(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(actual));

    public static string SharePath(string shareId) => SharePathRoot + shareId + "/";

    public static string LinkPath(string token) => LinkRoot + token;

    public static string Exposure(bool enabled, bool authEnabled) =>
        !enabled ? ExposureDisabled : authEnabled ? ExposureProtected : ExposurePublic;

    /// <summary>API timestamp: <c>YYYY-MM-DDTHH:MM:SSZ</c>, never a fraction.</summary>
    public static string Stamp(long epochSeconds) =>
        DateTimeOffset.FromUnixTimeSeconds(epochSeconds).UtcDateTime
            .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    public static long ParseStamp(string text) =>
        new DateTimeOffset(DateTime.SpecifyKind(DateTime.ParseExact(text, "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture), DateTimeKind.Utc)).ToUnixTimeSeconds();

    // ----------------------------------------------------------------------------------------------
    // Paths

    /// <summary>
    /// RFC 3986 §6.2.2 syntax normalisation of an already percent-encoded path: escapes of
    /// unreserved characters are decoded and every other escape gets upper-case hex. Null for a
    /// path that is not plain ASCII pchar/"/"/escapes or that has a malformed escape. The result
    /// only decides the scope; the request is forwarded with its original raw path.
    /// </summary>
    public static string? NormalizePath(string raw)
    {
        var builder = new StringBuilder(raw.Length);
        var i = 0;
        while (i < raw.Length)
        {
            var ch = raw[i];
            if (ch == '%')
            {
                if (i + 3 > raw.Length || !IsHex(raw[i + 1]) || !IsHex(raw[i + 2]))
                {
                    return null;
                }
                var decoded = (char)Convert.ToInt32(raw.Substring(i + 1, 2), 16);
                if (Unreserved.Contains(decoded, StringComparison.Ordinal))
                {
                    builder.Append(decoded);
                }
                else
                {
                    builder.Append('%').Append(char.ToUpperInvariant(raw[i + 1]))
                        .Append(char.ToUpperInvariant(raw[i + 2]));
                }
                i += 3;
                continue;
            }
            if (!PathChars.Contains(ch, StringComparison.Ordinal))
            {
                return null;
            }
            builder.Append(ch);
            i++;
        }
        return builder.ToString();
    }

    /// <summary>
    /// A normalized path that could step outside a prefix once the target decodes it: a dot
    /// segment, or an escaped slash, backslash or control character.
    /// </summary>
    public static bool UnsafeForPrefix(string normalized)
    {
        for (var i = 0; i + 2 < normalized.Length; i++)
        {
            if (normalized[i] != '%')
            {
                continue;
            }
            var code = Convert.ToInt32(normalized.Substring(i + 1, 2), 16);
            if (code is 0x2F or 0x5C or < 0x20 or 0x7F)
            {
                return true;
            }
            i += 2;
        }
        var segments = normalized.Split('/');
        for (var s = 1; s < segments.Length; s++)
        {
            if (segments[s] is "." or "..")
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>The stored form of a pathPrefix, or null when it must be rejected with 400.</summary>
    public static string? CanonicalPrefix(string? value)
    {
        if (value is null || !value.StartsWith('/') || value.StartsWith("//", StringComparison.Ordinal))
        {
            return null;
        }
        var normalized = NormalizePath(value);
        if (normalized is null || UnsafeForPrefix(normalized))
        {
            return null;
        }
        var inner = normalized.Length == 1 ? string.Empty
            : normalized.EndsWith('/') ? normalized[1..^1] : normalized[1..];
        if (inner.Length > 0 && inner.Split('/').Any(static segment => segment.Length == 0))
        {
            return null;
        }
        var canonical = normalized.EndsWith('/') ? normalized : normalized + "/";
        return Encoding.ASCII.GetByteCount(canonical) > PathPrefixMaxBytes ? null : canonical;
    }

    public static bool PathInScope(string prefix, string relativePath)
    {
        if (prefix == "/")
        {
            // The whole route: no rule beyond the route's own.
            return true;
        }
        var normalized = NormalizePath(relativePath);
        if (normalized is null || UnsafeForPrefix(normalized))
        {
            return false;
        }
        return normalized == prefix[..^1] || normalized.StartsWith(prefix, StringComparison.Ordinal);
    }

    /// <summary>The refusal for a request outside the share's scope, or null when it is inside.</summary>
    public static HttpShareRefusal? ScopeDecision(string access, string pathPrefix, string method,
        string relativePath, bool upgrade)
    {
        if (access == AccessRead)
        {
            if (!ReadMethods.Contains(method, StringComparer.Ordinal))
            {
                return new HttpShareRefusal(StatusCodes.Status405MethodNotAllowed,
                    HttpShareCodes.MethodNotAllowed);
            }
            if (upgrade)
            {
                return new HttpShareRefusal(StatusCodes.Status403Forbidden, HttpShareCodes.ScopeDenied);
            }
        }
        return PathInScope(pathPrefix, relativePath)
            ? null
            : new HttpShareRefusal(StatusCodes.Status403Forbidden, HttpShareCodes.ScopeDenied);
    }

    private static bool IsHex(char ch) =>
        ch is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    // ----------------------------------------------------------------------------------------------
    // Cookies and headers

    private static IEnumerable<string> CookiePairs(IEnumerable<string?> cookieHeaders)
    {
        foreach (var header in cookieHeaders)
        {
            if (header is null)
            {
                continue;
            }
            foreach (var part in header.Split(';'))
            {
                var pair = part.Trim(' ', '\t');
                if (pair.Length > 0)
                {
                    yield return pair;
                }
            }
        }
    }

    private static string PairName(string pair) => pair.Split('=', 2)[0].Trim(' ', '\t');

    private static string PairValue(string pair)
    {
        var separator = pair.IndexOf('=', StringComparison.Ordinal);
        return separator < 0 ? string.Empty : pair[(separator + 1)..].Trim(' ', '\t');
    }

    /// <summary>
    /// Values of the share cookie that name this share, in order, at most four. A page on the same
    /// origin can plant a second cookie of the same name with a longer Path; the browser sends it
    /// first, so the server tries a few values instead of only the first one.
    /// </summary>
    public static IReadOnlyList<string> CredentialCandidates(IEnumerable<string?> cookieHeaders,
        string shareId)
    {
        var candidates = new List<string>();
        foreach (var pair in CookiePairs(cookieHeaders))
        {
            if (!string.Equals(PairName(pair), CookieName, StringComparison.Ordinal))
            {
                continue;
            }
            var value = PairValue(pair);
            if (string.Equals(ParseToken(value), shareId, StringComparison.Ordinal))
            {
                candidates.Add(value);
                if (candidates.Count == MaxCookieCandidates)
                {
                    break;
                }
            }
        }
        return candidates;
    }

    /// <summary>The single Cookie header sent to the device: every pair except the share cookie.</summary>
    public static string? ForwardedCookie(IEnumerable<string?> cookieHeaders)
    {
        var kept = CookiePairs(cookieHeaders)
            .Where(static pair => !string.Equals(PairName(pair), CookieName, StringComparison.Ordinal))
            .ToList();
        return kept.Count == 0 ? null : string.Join("; ", kept);
    }

    /// <summary>
    /// An upstream Set-Cookie value confined to the share path, or null when it is dropped. Every
    /// route and share lives on one origin; a cookie set with Path=/ or a Domain by one target
    /// would otherwise be sent to every other route and share the visitor opens.
    /// </summary>
    public static string? ScopeSetCookie(string value, string shareId)
    {
        var parts = value.Split(';');
        var name = parts[0].Split('=', 2)[0].Trim(' ', '\t');
        if (string.Equals(name, CookieName, StringComparison.Ordinal)
            || name.StartsWith("__host-", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        var output = new List<string> { parts[0].Trim(' ', '\t') };
        foreach (var part in parts.Skip(1))
        {
            var attribute = part.Trim(' ', '\t');
            if (attribute.Length == 0)
            {
                continue;
            }
            var key = attribute.Split('=', 2)[0].Trim(' ', '\t').ToLowerInvariant();
            if (key == "domain")
            {
                continue;
            }
            if (key == "path")
            {
                var path = attribute.Contains('=', StringComparison.Ordinal)
                    ? attribute.Split('=', 2)[1].Trim(' ', '\t')
                    : string.Empty;
                if (path.StartsWith('/'))
                {
                    attribute = "Path=" + SharePathRoot + shareId + path;
                }
            }
            output.Add(attribute);
        }
        return string.Join("; ", output);
    }

    /// <summary>
    /// Headers relayed to a share visitor after the route's own response rules, as
    /// <c>Name:value</c> lines. Set-Cookie is confined to the share path, Clear-Site-Data is
    /// dropped because it would wipe the whole origin, and the cache headers are replaced so no
    /// shared cache keeps a copy and the browser revalidates every reuse. A 101 only gets the
    /// cookie and Clear-Site-Data rules.
    /// </summary>
    public static List<string> ResponseHeaders(int status, IEnumerable<string> headers, string shareId)
    {
        var noStore = false;
        var output = new List<string>();
        foreach (var header in headers)
        {
            var separator = header.IndexOf(':', StringComparison.Ordinal);
            var name = separator < 0 ? header : header[..separator];
            var value = separator < 0 ? string.Empty : header[(separator + 1)..];
            var lowered = name.Trim().ToLowerInvariant();
            if (lowered == "clear-site-data")
            {
                continue;
            }
            if (lowered == "set-cookie")
            {
                var scoped = ScopeSetCookie(value.Trim(' ', '\t'), shareId);
                if (scoped is not null)
                {
                    output.Add(name.Trim() + ":" + scoped);
                }
                continue;
            }
            if (status != StatusCodes.Status101SwitchingProtocols && CacheHeaders.Contains(lowered))
            {
                if (lowered == "cache-control")
                {
                    noStore |= value.Split(',')
                        .Any(static directive => directive.Trim().Split('=', 2)[0]
                            .Equals("no-store", StringComparison.OrdinalIgnoreCase));
                }
                continue;
            }
            output.Add(header);
        }
        if (status != StatusCodes.Status101SwitchingProtocols)
        {
            output.Add("Cache-Control:" + (noStore ? "private, no-store" : "private, no-cache"));
        }
        return output;
    }

    /// <summary>The cookie the exchange sets: exactly the share path, as long as the share lives.</summary>
    public static string SetCookieHeader(string shareId, string token, long maxAgeSeconds) =>
        $"{CookieName}={token}; Path={SharePath(shareId)}; Max-Age={maxAgeSeconds.ToString(CultureInfo.InvariantCulture)}; HttpOnly; Secure; SameSite=Strict";

    /// <summary>Clears the share cookie once the share has ended.</summary>
    public static string ClearCookieHeader(string shareId) =>
        $"{CookieName}=; Path={SharePath(shareId)}; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
}

/// <summary>Error codes of the share API and the share path.</summary>
public static class HttpShareCodes
{
    public const string RequestInvalid = "SHARE_REQUEST_INVALID";
    public const string Unavailable = "SHARE_UNAVAILABLE";
    public const string RouteNotFound = "SHARE_ROUTE_NOT_FOUND";
    public const string RouteDisabled = "SHARE_ROUTE_DISABLED";
    public const string ClientDisabled = "SHARE_CLIENT_DISABLED";
    public const string RoutePublic = "SHARE_ROUTE_PUBLIC";
    public const string LimitReached = "SHARE_LIMIT_REACHED";
    public const string NotFound = "SHARE_NOT_FOUND";
    public const string RateLimited = "SHARE_RATE_LIMITED";
    public const string Revoked = "SHARE_REVOKED";
    public const string Expired = "SHARE_EXPIRED";
    public const string MethodNotAllowed = "SHARE_METHOD_NOT_ALLOWED";
    public const string ScopeDenied = "SHARE_SCOPE_DENIED";
    public const string Busy = "SHARE_BUSY";
    public const string Forbidden = "SHARE_FORBIDDEN";
}

public sealed record HttpShareRefusal(int StatusCode, string Code);
