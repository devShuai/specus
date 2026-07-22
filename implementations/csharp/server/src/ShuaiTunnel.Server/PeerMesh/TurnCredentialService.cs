using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.PeerMesh;

/// <summary>Issues and validates Java-compatible ephemeral TURN long-term credentials.</summary>
public sealed class TurnCredentialService
{
    private readonly PeerMeshOptions _options;
    private readonly byte[] _runtimeSecret = RandomNumberGenerator.GetBytes(32);
    private readonly string _nonce = Base64Url(RandomNumberGenerator.GetBytes(18));

    public TurnCredentialService(IOptions<PeerMeshOptions> options)
    {
        _options = options.Value;
    }

    public bool AuthRequired => _options.TurnAuthRequired;
    public string Realm => string.IsNullOrWhiteSpace(_options.TurnRealm)
        ? "shuai-tunnel"
        : _options.TurnRealm.Trim();
    public string Nonce => _nonce;

    public TurnCredential Issue(string? subject)
    {
        var ttl = Math.Max(60L, _options.TurnCredentialTtlSeconds);
        var expiresAt = DateTimeOffset.UtcNow.AddSeconds(ttl);
        var safeSubject = SanitizeSubject(subject);
        var username = $"{expiresAt.ToUnixTimeSeconds()}:{safeSubject}:{RandomNumberGenerator.GetHexString(4).ToLowerInvariant()}";
        return new TurnCredential(username, CredentialForUsername(username), Realm, Nonce, expiresAt);
    }

    public string CredentialForUsername(string username)
    {
        using var hmac = new HMACSHA1(Secret());
        return Base64Url(hmac.ComputeHash(Encoding.UTF8.GetBytes(username)));
    }

    public bool UsernameCredentialValid(string? username, string? credential)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(credential))
        {
            return false;
        }
        var separator = username.IndexOf(':');
        var expiresText = separator < 0 ? username : username[..separator];
        if (!long.TryParse(expiresText, out var expiresAt))
        {
            return false;
        }
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (expiresAt <= now || expiresAt - now > Math.Max(60L, _options.TurnCredentialTtlSeconds) + 60L)
        {
            return false;
        }
        var expected = Encoding.UTF8.GetBytes(CredentialForUsername(username));
        var actual = Encoding.UTF8.GetBytes(credential.Trim());
        return expected.Length == actual.Length
            && CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    public byte[] LongTermKey(string username, string credential) =>
        MD5.HashData(Encoding.UTF8.GetBytes($"{username}:{Realm}:{credential}"));

    /// <summary>Subject prefix used by public transfer (browser WebRTC) credentials.</summary>
    public const string GeneralSubjectPrefix = "public-transfer";

    /// <summary>
    /// Browser WebRTC relays DTLS/SRTP through TURN, which cannot pass the Peer Mesh specific
    /// checks, so those allocations must be forwarded with standard TURN semantics under their
    /// own quotas and destination policy.
    /// </summary>
    public bool IsGeneralRelaySubject(string? username)
    {
        var parts = username?.Trim().Split(':', 3);
        return parts is { Length: 3 }
            && parts[1].StartsWith(GeneralSubjectPrefix, StringComparison.Ordinal);
    }

    public long PeerMeshClientId(string? username)
    {
        var parts = username?.Trim().Split(':', 3);
        return parts is { Length: 3 }
            && parts[1].StartsWith("pm-", StringComparison.Ordinal)
            && long.TryParse(parts[1].AsSpan(3), out var clientId)
            && clientId > 0
                ? clientId
                : 0;
    }

    private byte[] Secret() => string.IsNullOrWhiteSpace(_options.TurnSharedSecret)
        ? _runtimeSecret
        : Encoding.UTF8.GetBytes(_options.TurnSharedSecret.Trim());

    private static string SanitizeSubject(string? subject)
    {
        var value = string.IsNullOrWhiteSpace(subject) ? "peer" : subject.Trim();
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            builder.Append(char.IsAsciiLetterOrDigit(ch) || ch is '_' or '.' or '-'
                ? ch
                : '_');
        }
        return builder.ToString();
    }

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public sealed record TurnCredential(string Username, string Credential, string Realm, string Nonce,
    DateTimeOffset ExpiresAt);
