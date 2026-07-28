using System.Security.Cryptography;
using System.Text;
using Specus.Client.Configuration;

namespace Specus.Client.PeerMesh;

/// <summary>
/// Applies RFC 5389/5766 long-term credentials to authenticated TURN requests.
/// STUN binding requests and TURN indications intentionally remain unauthenticated.
/// </summary>
internal sealed class TurnLongTermAuthenticator
{
    private readonly object _sync = new();
    private Credentials _credentials = Credentials.Empty;

    public bool Update(PeerMeshConfig? config)
    {
        var next = config is null
            ? Credentials.Empty
            : new Credentials(
                Normalize(config.IceUsername),
                Normalize(config.IceCredential),
                Normalize(config.IceRealm),
                Normalize(config.IceNonce));
        lock (_sync)
        {
            if (_credentials == next)
            {
                return false;
            }
            _credentials = next;
            return true;
        }
    }

    public bool CanAuthenticate
    {
        get
        {
            lock (_sync)
            {
                return _credentials.Complete;
            }
        }
    }

    public byte[] Encode(StunMessage request)
    {
        if (!RequiresAuthentication(request.Type))
        {
            return request.ToBytes();
        }

        Credentials credentials;
        lock (_sync)
        {
            credentials = _credentials;
        }
        if (!credentials.Complete)
        {
            return request.ToBytes();
        }

        var attributes = request.Attributes
            .Where(attribute => !IsAuthenticationAttribute(attribute.Type))
            .ToList();
        attributes.Add(StunMessage.Username(credentials.Username));
        attributes.Add(StunMessage.Realm(credentials.Realm));
        attributes.Add(StunMessage.Nonce(credentials.Nonce));
        var authenticated = new StunMessage(request.Type, request.TransactionId, attributes);
        return authenticated.ToBytes(LongTermKey(credentials));
    }

    public bool ApplyChallenge(StunMessage response)
    {
        var code = response.ErrorCode();
        if (code is not (401 or 438))
        {
            return false;
        }

        lock (_sync)
        {
            if (!HasText(_credentials.Username) || !HasText(_credentials.Credential))
            {
                return false;
            }
            var realm = FirstText(response.TextAttribute(StunMessage.AttrRealm), _credentials.Realm);
            var nonce = FirstText(response.TextAttribute(StunMessage.AttrNonce), _credentials.Nonce);
            var next = new Credentials(_credentials.Username, _credentials.Credential, realm, nonce);
            if (!next.Complete)
            {
                return false;
            }
            _credentials = next;
            return true;
        }
    }

    public static bool RequiresAuthentication(ushort messageType) =>
        messageType is StunMessage.AllocateRequest
            or StunMessage.RefreshRequest
            or StunMessage.CreatePermissionRequest
			or StunMessage.ChannelBindRequest;

    private static bool IsAuthenticationAttribute(ushort attributeType) =>
        attributeType is StunMessage.AttrUsername
            or StunMessage.AttrRealm
            or StunMessage.AttrNonce
            or StunMessage.AttrMessageIntegrity;

    private static byte[] LongTermKey(Credentials credentials) =>
        MD5.HashData(Encoding.UTF8.GetBytes(
            $"{credentials.Username}:{credentials.Realm}:{credentials.Credential}"));

    private static string Normalize(string? value) => value?.Trim() ?? "";

    private static string FirstText(string? value, string fallback) =>
        HasText(value) ? value!.Trim() : fallback;

    private static bool HasText(string? value) => !string.IsNullOrWhiteSpace(value);

    private sealed record Credentials(string Username, string Credential, string Realm, string Nonce)
    {
        public static Credentials Empty { get; } = new("", "", "", "");

        public bool Complete =>
            HasText(Username) && HasText(Credential) && HasText(Realm) && HasText(Nonce);
    }
}
