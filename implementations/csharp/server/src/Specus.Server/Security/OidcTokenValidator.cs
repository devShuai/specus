using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Management;

namespace Specus.Server.Security;

public sealed class AdminBearerTokenValidator
{
    private readonly LocalTokenService _localTokens;
    private readonly OidcTokenValidator _oidcTokens;
    private readonly ManagementUserService _users;

    public AdminBearerTokenValidator(LocalTokenService localTokens, OidcTokenValidator oidcTokens,
        ManagementUserService users)
    {
        _localTokens = localTokens;
        _oidcTokens = oidcTokens;
        _users = users;
    }

    public async ValueTask<ClaimsPrincipal?> ValidateAsync(string? token,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var algorithm = JwtTokenUtility.ReadAlgorithm(token);
        if (algorithm.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
        {
            var signedPrincipal = _localTokens.Validate(token);
            var subject = signedPrincipal?.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? signedPrincipal?.Identity?.Name;
            if (signedPrincipal is null
                || !string.Equals(signedPrincipal.FindFirst("iss")?.Value,
                    LocalTokenService.Issuer, StringComparison.Ordinal))
            {
                return null;
            }
            var current = await _users.ResolveRefreshUserAsync(subject, cancellationToken)
                .ConfigureAwait(false);
            return current is null
                ? null
                : CreateLocalPrincipal(current, LocalTokenService.Issuer, "LocalBearer");
        }

        var externalIdentity = await _oidcTokens.ValidateBearerAsync(token, cancellationToken)
            .ConfigureAwait(false);
        if (externalIdentity is null)
        {
            return null;
        }

        // A valid token is not, by itself, a Specus account. Only an already-bound, enabled
        // issuer/subject may use the management API, and tenant/role always come from local DB.
        var user = await _users.ResolveBoundOidcUserAsync(externalIdentity.Issuer,
                externalIdentity.Subject, cancellationToken)
            .ConfigureAwait(false);
        if (user is null)
        {
            return null;
        }

        var identity = new ClaimsIdentity("OidcBearer");
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Username));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Username));
        identity.AddClaim(new Claim("iss", externalIdentity.Issuer));
        identity.AddClaim(new Claim("oidc_sub", externalIdentity.Subject));
        identity.AddClaim(new Claim("tenant_id", user.TenantId));
        identity.AddClaim(new Claim(ClaimTypes.Role, ManagementContext.RoleWire(user.Role)));
        identity.AddClaim(new Claim("role", ManagementContext.RoleWire(user.Role)));
        return new ClaimsPrincipal(identity);
    }

    private static ClaimsPrincipal CreateLocalPrincipal(LoginUser user, string issuer,
        string authenticationType)
    {
        var identity = new ClaimsIdentity(authenticationType);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Username));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Username));
        identity.AddClaim(new Claim("iss", issuer));
        identity.AddClaim(new Claim("tenant_id", user.TenantId));
        identity.AddClaim(new Claim(ClaimTypes.Role, ManagementContext.RoleWire(user.Role)));
        identity.AddClaim(new Claim("role", ManagementContext.RoleWire(user.Role)));
        return new ClaimsPrincipal(identity);
    }

}

public sealed class OidcTokenValidator
{
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan KeyCacheTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RetiredKeyOverlapTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RefreshCooldown = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan RefreshTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan UnknownKeyNegativeTtl = TimeSpan.FromSeconds(30);
    internal const int MaximumJwksResponseBytes = 1024 * 1024;
    internal const int MaximumUnknownKeyEntries = 4096;
    // A valid 2048-bit RSA JWK is already hundreds of bytes, so a 1 MiB JWKS cannot approach
    // this count. Keep the no-kid verification loop explicitly bounded even if parsing changes.
    internal const int MaximumSignatureCandidates = 8192;

    private readonly OidcOptions _options;
    private readonly IOidcJwkProvider _jwkProvider;
    private readonly ILogger<OidcTokenValidator> _logger;
    private readonly SemaphoreSlim _keyLock = new(1, 1);
    private readonly object _unknownKeyLock = new();
    private readonly Dictionary<string, long> _unknownKeyExpirations =
        new(StringComparer.Ordinal);

    private IReadOnlyList<RsaJwk> _cachedKeys = [];
    private IReadOnlyList<RsaJwk> _activeKeys = [];
    private IReadOnlyList<RetiredRsaJwk> _retiredKeys = [];
    private Task<KeySnapshot>? _refreshTask;
    private long _keysExpiresAtTicks;
    private long _lastRefreshAttemptTicks;
    private long _lastForcedRefreshAttemptTicks;
    private long _keyVersion;

    public OidcTokenValidator(IOptions<OidcOptions> options,
        IOidcJwkProvider jwkProvider,
        ILogger<OidcTokenValidator> logger)
    {
        _options = options.Value;
        _jwkProvider = jwkProvider;
        _logger = logger;
    }

    internal int UnknownKeyCacheCountForTests
    {
        get
        {
            lock (_unknownKeyLock)
            {
                return _unknownKeyExpirations.Count;
            }
        }
    }

    public async ValueTask<ValidatedOidcBearer?> ValidateBearerAsync(string token,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.Issuer)
            || string.IsNullOrWhiteSpace(_options.Audience))
        {
            return null;
        }

        var payload = await ValidateSignedTokenAsync(token, cancellationToken).ConfigureAwait(false);
        var audience = _options.Audience;
        return payload is not null
               && payload.Audiences.Contains(audience, StringComparer.Ordinal)
            ? new ValidatedOidcBearer(payload.Issuer!, payload.Subject)
            : null;
    }

    public async ValueTask<ValidatedOidcToken?> ValidateIdTokenAsync(string token,
        string expectedNonce, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(expectedNonce)
            || string.IsNullOrWhiteSpace(_options.Issuer)
            || string.IsNullOrWhiteSpace(_options.ClientId))
        {
            return null;
        }

        var payload = await ValidateSignedTokenAsync(token, cancellationToken).ConfigureAwait(false);
        if (payload is null)
        {
            return null;
        }

        var clientId = _options.ClientId;
        var audiences = payload.Audiences;
        if (!audiences.Contains(clientId, StringComparer.Ordinal)
            || (!string.IsNullOrWhiteSpace(payload.AuthorizedParty)
                && !string.Equals(payload.AuthorizedParty, clientId, StringComparison.Ordinal))
            || (audiences.Count > 1
                && !string.Equals(payload.AuthorizedParty, clientId, StringComparison.Ordinal))
            || string.IsNullOrWhiteSpace(payload.PreferredUsername)
            || !ConstantTimeEquals(expectedNonce, payload.Nonce))
        {
            return null;
        }

        return new ValidatedOidcToken(payload.Issuer!, payload.Subject,
            payload.PreferredUsername, payload.TenantId);
    }

    private async ValueTask<TokenPayload?> ValidateSignedTokenAsync(string token,
        CancellationToken cancellationToken)
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
            if (!header.Algorithm.Equals("RS256", StringComparison.Ordinal))
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

        if (!ValidateBaseClaims(payload))
        {
            return null;
        }

        var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        var selected = await FindKeysAsync(header.KeyId, cancellationToken).ConfigureAwait(false);
        if (selected is null)
        {
            return null;
        }
        if (!VerifyAnySignature(selected.Keys, signingInput, signature))
        {
            var refreshed = await RefreshKeysAsync(selected.Version, force: true,
                    cancellationToken)
                .ConfigureAwait(false);
            var refreshedKeys = SelectKeys(refreshed.Keys, header.KeyId);
            if (refreshedKeys.Count == 0
                || !VerifyAnySignature(refreshedKeys, signingInput, signature))
            {
                return null;
            }
        }
        return payload;
    }

    private bool ValidateBaseClaims(TokenPayload payload)
    {
        var now = DateTimeOffset.UtcNow;
        if (string.IsNullOrWhiteSpace(payload.Issuer)
            || string.IsNullOrWhiteSpace(payload.Subject))
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

        return true;
    }

    private async Task<KeySelection?> FindKeysAsync(string? keyId,
        CancellationToken cancellationToken)
    {
        if (keyId is { Length: > 256 })
        {
            return null;
        }

        var snapshot = await GetKeysAsync(cancellationToken).ConfigureAwait(false);
        var keys = SelectKeys(snapshot.Keys, keyId);
        if (keys.Count > 0)
        {
            return new KeySelection(keys, snapshot.Version);
        }
        if (keyId is null)
        {
            return null;
        }

        var nowTicks = DateTimeOffset.UtcNow.UtcTicks;
        if (IsUnknownKeyCached(keyId, nowTicks))
        {
            return null;
        }

        // A new kid is the normal key-rotation signal. Refresh once for the cache generation that
        // missed it; concurrent misses share that refresh and repeated random kids hit cooldown.
        snapshot = await RefreshKeysAsync(snapshot.Version, force: true, cancellationToken)
            .ConfigureAwait(false);
        keys = SelectKeys(snapshot.Keys, keyId);
        if (keys.Count > 0)
        {
            return new KeySelection(keys, snapshot.Version);
        }
        RememberUnknownKey(keyId);
        return null;
    }

    private static IReadOnlyList<RsaJwk> SelectKeys(
        IReadOnlyList<RsaJwk> keys, string? keyId)
    {
        if (keyId is not null)
        {
            return keys.Where(key => string.Equals(key.KeyId, keyId, StringComparison.Ordinal))
                .Take(MaximumSignatureCandidates)
                .ToArray();
        }

        // Nimbus leaves the JWK matcher's kid constraint unset when the JOSE header has no kid,
        // then DefaultJWTProcessor tries every kty/use/alg-compatible candidate in order.
        return keys.Count <= MaximumSignatureCandidates
            ? keys
            : keys.Take(MaximumSignatureCandidates).ToArray();
    }

    private Task<KeySnapshot> GetKeysAsync(CancellationToken cancellationToken)
    {
        var nowTicks = DateTimeOffset.UtcNow.UtcTicks;
        var keys = Volatile.Read(ref _cachedKeys);
        var version = Interlocked.Read(ref _keyVersion);
        if (nowTicks < Interlocked.Read(ref _keysExpiresAtTicks))
        {
            return Task.FromResult(new KeySnapshot(keys, version));
        }
        return RefreshKeysAsync(observedVersion: -1, force: false, cancellationToken);
    }

    private async Task<KeySnapshot> RefreshKeysAsync(long observedVersion, bool force,
        CancellationToken cancellationToken)
    {
        Task<KeySnapshot>? refreshTask = null;
        await _keyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var currentKeys = Volatile.Read(ref _cachedKeys);
            var currentVersion = Interlocked.Read(ref _keyVersion);
            var nowTicks = DateTimeOffset.UtcNow.UtcTicks;
            if (observedVersion >= 0 && currentVersion != observedVersion)
            {
                return new KeySnapshot(currentKeys, currentVersion);
            }
            if (_refreshTask is { IsCompleted: false } activeRefresh)
            {
                refreshTask = activeRefresh;
            }
            else
            {
                if (!force && nowTicks < Interlocked.Read(ref _keysExpiresAtTicks))
                {
                    return new KeySnapshot(currentKeys, currentVersion);
                }
                var lastAttempt = force
                    ? Interlocked.Read(ref _lastForcedRefreshAttemptTicks)
                    : Interlocked.Read(ref _lastRefreshAttemptTicks);
                if (lastAttempt != 0 && nowTicks - lastAttempt < RefreshCooldown.Ticks)
                {
                    return new KeySnapshot(currentKeys, currentVersion);
                }
                refreshTask = FetchKeysAsync(force);
                _refreshTask = refreshTask;
            }
        }
        finally
        {
            _keyLock.Release();
        }

        // Caller cancellation only abandons this wait. The bounded shared refresh continues for
        // other requests and updates the process-wide key generation.
        return await refreshTask.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<KeySnapshot> FetchKeysAsync(bool force)
    {
        using var timeout = new CancellationTokenSource(RefreshTimeout);
        try
        {
            var jwksUri = new Uri(_options.JwkSetUri, UriKind.Absolute);
            var body = await _jwkProvider.GetJwksAsync(jwksUri, timeout.Token)
                .ConfigureAwait(false);
            if (Encoding.UTF8.GetByteCount(body) > MaximumJwksResponseBytes)
            {
                throw new InvalidDataException("JWKS response exceeds size limit");
            }
            var refreshedKeys = ParseJwks(body);
            var now = DateTimeOffset.UtcNow;
            var effectiveKeys = RotateKeys(refreshedKeys, now);
            Volatile.Write(ref _cachedKeys, effectiveKeys);
            var currentVersion = Interlocked.Increment(ref _keyVersion);
            Interlocked.Exchange(ref _keysExpiresAtTicks, now.Add(KeyCacheTtl).UtcTicks);
            lock (_unknownKeyLock)
            {
                _unknownKeyExpirations.Clear();
            }
            return new KeySnapshot(effectiveKeys, currentVersion);
        }
        catch (OperationCanceledException ex) when (timeout.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "[oidc] JWKS refresh timed out");
            return RetainKeysAfterRefreshFailure();
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or UriFormatException
            or FormatException or InvalidOperationException or InvalidDataException or IOException)
        {
            _logger.LogWarning(ex, "[oidc] failed to refresh JWKS");
            // Retain the last healthy generation. A transient IdP/JWKS outage must not erase all
            // usable signing keys; the short retry TTL and cooldown bound subsequent fetch load.
            return RetainKeysAfterRefreshFailure();
        }
        finally
        {
            // Cooldown starts only after the independent refresh completes.
            var completedAt = DateTimeOffset.UtcNow.UtcTicks;
            Interlocked.Exchange(ref _lastRefreshAttemptTicks, completedAt);
            if (force)
            {
                Interlocked.Exchange(ref _lastForcedRefreshAttemptTicks, completedAt);
            }
        }
    }

    private IReadOnlyList<RsaJwk> RotateKeys(IReadOnlyList<RsaJwk> refreshedKeys,
        DateTimeOffset now)
    {
        var retired = _retiredKeys
            .Where(item => item.ExpiresAtTicks > now.UtcTicks
                && !ContainsKeyIdentity(refreshedKeys, item.Key))
            .ToList();
        foreach (var previous in _activeKeys)
        {
            if (!ContainsKeyIdentity(refreshedKeys, previous)
                && !retired.Any(item => SameKeyIdentity(item.Key, previous)))
            {
                retired.Add(new RetiredRsaJwk(previous,
                    now.Add(RetiredKeyOverlapTtl).UtcTicks));
            }
        }
        _activeKeys = refreshedKeys;
        _retiredKeys = retired;
        return [.. refreshedKeys, .. retired.Select(item => item.Key)];
    }

    private KeySnapshot RetainKeysAfterRefreshFailure()
    {
        var now = DateTimeOffset.UtcNow;
        var retained = _retiredKeys.Where(item => item.ExpiresAtTicks > now.UtcTicks).ToArray();
        if (retained.Length != _retiredKeys.Count)
        {
            _retiredKeys = retained;
            Volatile.Write(ref _cachedKeys,
                [.. _activeKeys, .. retained.Select(item => item.Key)]);
            Interlocked.Increment(ref _keyVersion);
        }
        Interlocked.Exchange(ref _keysExpiresAtTicks, now.Add(RefreshCooldown).UtcTicks);
        return new KeySnapshot(Volatile.Read(ref _cachedKeys),
            Interlocked.Read(ref _keyVersion));
    }

    private static bool ContainsKeyIdentity(IReadOnlyList<RsaJwk> keys, RsaJwk expected) =>
        keys.Any(key => SameKeyIdentity(key, expected));

    private static bool SameKeyIdentity(RsaJwk left, RsaJwk right)
    {
        if (!string.IsNullOrWhiteSpace(left.KeyId) || !string.IsNullOrWhiteSpace(right.KeyId))
        {
            return string.Equals(left.KeyId, right.KeyId, StringComparison.Ordinal);
        }
        return left.Modulus.AsSpan().SequenceEqual(right.Modulus)
            && left.Exponent.AsSpan().SequenceEqual(right.Exponent);
    }

    private static bool VerifySignature(RsaJwk key, byte[] signingInput, byte[] signature)
    {
        try
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
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool VerifyAnySignature(IReadOnlyList<RsaJwk> keys,
        byte[] signingInput, byte[] signature)
    {
        foreach (var key in keys)
        {
            if (VerifySignature(key, signingInput, signature))
            {
                return true;
            }
        }
        return false;
    }

    private bool IsUnknownKeyCached(string keyId, long nowTicks)
    {
        lock (_unknownKeyLock)
        {
            if (!_unknownKeyExpirations.TryGetValue(keyId, out var expiresAt))
            {
                return false;
            }
            if (nowTicks < expiresAt)
            {
                return true;
            }
            _unknownKeyExpirations.Remove(keyId);
            return false;
        }
    }

    private void RememberUnknownKey(string keyId)
    {
        var nowTicks = DateTimeOffset.UtcNow.UtcTicks;
        lock (_unknownKeyLock)
        {
            if (_unknownKeyExpirations.Count >= MaximumUnknownKeyEntries)
            {
                foreach (var expired in _unknownKeyExpirations
                             .Where(item => item.Value <= nowTicks)
                             .Select(item => item.Key)
                             .ToArray())
                {
                    _unknownKeyExpirations.Remove(expired);
                }
            }
            if (_unknownKeyExpirations.Count < MaximumUnknownKeyEntries)
            {
                _unknownKeyExpirations[keyId] = DateTimeOffset.UtcNow
                    .Add(UnknownKeyNegativeTtl).UtcTicks;
            }
        }
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
        var preferredUsername = ReadClaimAsString(root, "preferred_username");
        return new TokenPayload(
            ReadClaimAsString(root, "iss"),
            subject,
            name,
            preferredUsername,
            ReadAudiences(root),
            ReadUnixTime(root, "exp"),
            ReadUnixTime(root, "nbf"),
            ReadClaimAsString(root, TenantClaimName(_options.TenantClaim)),
            ReadClaimAsString(root, "nonce"),
            ReadClaimAsString(root, "azp"));
    }

    private static IReadOnlyList<RsaJwk> ParseJwks(string body)
    {
        using var document = JsonDocument.Parse(body);
        if (!document.RootElement.TryGetProperty("keys", out var keysElement)
            || keysElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("JWKS keys array is missing");
        }

        var keys = new List<RsaJwk>();
        foreach (var key in keysElement.EnumerateArray())
        {
            var kty = ReadString(key, "kty");
            var n = ReadString(key, "n");
            var e = ReadString(key, "e");
            var use = ReadString(key, "use");
            if (!string.Equals(kty, "RSA", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(n)
                || string.IsNullOrWhiteSpace(e)
                || (!string.IsNullOrWhiteSpace(use)
                    && !use.Equals("sig", StringComparison.Ordinal)))
            {
                continue;
            }

            var alg = ReadString(key, "alg");
            if (!string.IsNullOrWhiteSpace(alg)
                && !alg.Equals("RS256", StringComparison.Ordinal))
            {
                continue;
            }

            try
            {
                var modulus = TrimUnsignedInteger(JwtTokenUtility.Base64UrlDecode(n));
                var exponent = TrimUnsignedInteger(JwtTokenUtility.Base64UrlDecode(e));
                var keyId = ReadString(key, "kid");
                if (ModulusBitLength(modulus) < 2048
                    || !IsValidRsaExponent(exponent)
                    || keyId is { Length: > 256 })
                {
                    continue;
                }
                keys.Add(new RsaJwk(keyId, modulus, exponent));
            }
            catch (FormatException)
            {
                // Ignore malformed individual JWKs; healthy signing keys remain usable.
            }
        }

        return keys.Count > 0
            ? keys
            : throw new InvalidDataException("JWKS contains no usable RS256 signing key");
    }

    private static byte[] TrimUnsignedInteger(byte[] value)
    {
        var offset = 0;
        while (offset < value.Length - 1 && value[offset] == 0)
        {
            offset++;
        }
        return offset == 0 ? value : value[offset..];
    }

    private static int ModulusBitLength(byte[] modulus)
    {
        if (modulus.Length == 0)
        {
            return 0;
        }
        var first = modulus[0];
        var leadingZeroBits = 0;
        for (var mask = 0x80; mask != 0 && (first & mask) == 0; mask >>= 1)
        {
            leadingZeroBits++;
        }
        return modulus.Length * 8 - leadingZeroBits;
    }

    private static bool IsValidRsaExponent(byte[] exponent)
    {
        if (exponent.Length is 0 or > 4)
        {
            return false;
        }
        uint value = 0;
        foreach (var part in exponent)
        {
            value = (value << 8) | part;
        }
        return value >= 3 && (value & 1) == 1;
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
            // Nimbus/Spring exposes the original JSON string. Security-bound values such as iss,
            // nonce and azp must therefore retain whitespace for exact comparison. Username and
            // subject normalization remains the responsibility of ManagementUserService, just as
            // in the Java implementation.
            JsonValueKind.String => string.IsNullOrWhiteSpace(property.GetString())
                ? null
                : property.GetString(),
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

    private static bool ConstantTimeEquals(string expected, string? actual)
    {
        if (actual is null)
        {
            return false;
        }
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var actualBytes = Encoding.UTF8.GetBytes(actual);
        return expectedBytes.Length == actualBytes.Length
               && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }

    private sealed record TokenHeader(string Algorithm, string? KeyId);

    private sealed record TokenPayload(
        string? Issuer,
        string Subject,
        string? Name,
        string? PreferredUsername,
        IReadOnlyList<string> Audiences,
        DateTimeOffset? ExpiresAt,
        DateTimeOffset? NotBefore,
        string? TenantId,
        string? Nonce,
        string? AuthorizedParty);

    private sealed record RsaJwk(string? KeyId, byte[] Modulus, byte[] Exponent);
    private sealed record RetiredRsaJwk(RsaJwk Key, long ExpiresAtTicks);
    private sealed record KeySnapshot(IReadOnlyList<RsaJwk> Keys, long Version);
    private sealed record KeySelection(IReadOnlyList<RsaJwk> Keys, long Version);
}

public sealed record ValidatedOidcToken(
    string Issuer,
    string Subject,
    string PreferredUsername,
    string? TenantId);

public sealed record ValidatedOidcBearer(string Issuer, string Subject);

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

    public async Task<string> GetJwksAsync(Uri jwksUri,
        CancellationToken cancellationToken = default)
    {
        using var response = await HttpClient.GetAsync(jwksUri,
            HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > OidcTokenValidator.MaximumJwksResponseBytes)
        {
            throw new InvalidDataException("JWKS response exceeds size limit");
        }

        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            if (output.Length + read > OidcTokenValidator.MaximumJwksResponseBytes)
            {
                throw new InvalidDataException("JWKS response exceeds size limit");
            }
            output.Write(buffer, 0, read);
        }
        return new UTF8Encoding(false, true).GetString(output.GetBuffer(), 0,
            checked((int)output.Length));
    }
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
