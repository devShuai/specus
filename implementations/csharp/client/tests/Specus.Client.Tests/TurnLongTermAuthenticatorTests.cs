using System.Net;
using System.Security.Cryptography;
using System.Text;
using Specus.Client.Configuration;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

public sealed class TurnLongTermAuthenticatorTests
{
    private const string Username = "1900000000:client-a:01020304";
    private const string Credential = "turn-credential";
    private const string Realm = "specus";
    private const string Nonce = "login-nonce";

    [Theory]
    [InlineData(StunMessage.AllocateRequest)]
    [InlineData(StunMessage.RefreshRequest)]
    [InlineData(StunMessage.CreatePermissionRequest)]
    public void SignsEveryAuthenticatedTurnRequestType(ushort type)
    {
        var authenticator = Authenticator();
        var transactionId = TransactionId(type);
        var request = type switch
        {
            StunMessage.AllocateRequest => StunMessage.Of(
                type,
                transactionId,
                StunMessage.RequestedUdpTransportAttribute()),
            StunMessage.RefreshRequest => StunMessage.Of(
                type,
                transactionId,
                StunMessage.Lifetime(300)),
            _ => StunMessage.Of(
                type,
                transactionId,
                StunMessage.XorPeerAddress(new IPEndPoint(IPAddress.Parse("192.0.2.30"), 3478), transactionId)),
        };

        var encoded = authenticator.Encode(request);
        var parsed = StunMessage.Parse(encoded)!;

        Assert.Equal(Username, parsed.TextAttribute(StunMessage.AttrUsername));
        Assert.Equal(Realm, parsed.TextAttribute(StunMessage.AttrRealm));
        Assert.Equal(Nonce, parsed.TextAttribute(StunMessage.AttrNonce));
        Assert.NotNull(parsed.First(StunMessage.AttrMessageIntegrity));
        Assert.True(VerifyMessageIntegrity(encoded, LongTermKey(Realm)));
    }

    [Fact]
    public void BindingAndSendIndicationRemainUnsigned()
    {
        var authenticator = Authenticator();
        var bindingTransaction = TransactionId(4);
        var indicationTransaction = TransactionId(5);
        var requests = new[]
        {
            StunMessage.Of(
                StunMessage.BindingRequest,
                bindingTransaction,
                StunMessage.Software("test")),
            StunMessage.Of(
                StunMessage.SendIndication,
                indicationTransaction,
                StunMessage.XorPeerAddress(
                    new IPEndPoint(IPAddress.Parse("192.0.2.31"), 3478),
                    indicationTransaction),
                StunMessage.Data([1, 2, 3])),
        };

        foreach (var request in requests)
        {
            var encoded = authenticator.Encode(request);
            var parsed = StunMessage.Parse(encoded)!;

            Assert.Equal(request.ToBytes(), encoded);
            Assert.Null(parsed.First(StunMessage.AttrUsername));
            Assert.Null(parsed.First(StunMessage.AttrRealm));
            Assert.Null(parsed.First(StunMessage.AttrNonce));
            Assert.Null(parsed.First(StunMessage.AttrMessageIntegrity));
        }
    }

    [Fact]
    public void AppliesUnauthorizedAndStaleNonceChallengesButIgnoresOtherErrors()
    {
        var authenticator = Authenticator();
        Assert.False(authenticator.ApplyChallenge(StunMessage.Of(
            StunMessage.AllocateError,
            TransactionId(6),
            StunMessage.ErrorCode(400, "bad-request"),
            StunMessage.Realm("ignored-realm"),
            StunMessage.Nonce("ignored-nonce"))));

        foreach (var code in new[] { 401, 438 })
        {
            var challengedRealm = $"challenge-realm-{code}";
            var challengedNonce = $"challenge-nonce-{code}";
            Assert.True(authenticator.ApplyChallenge(StunMessage.Of(
                StunMessage.AllocateError,
                TransactionId(code),
                StunMessage.ErrorCode(code, "challenge"),
                StunMessage.Realm(challengedRealm),
                StunMessage.Nonce(challengedNonce))));

            var encoded = authenticator.Encode(StunMessage.Of(
                StunMessage.AllocateRequest,
                TransactionId(code + 1),
                StunMessage.RequestedUdpTransportAttribute()));
            var parsed = StunMessage.Parse(encoded)!;
            Assert.Equal(challengedRealm, parsed.TextAttribute(StunMessage.AttrRealm));
            Assert.Equal(challengedNonce, parsed.TextAttribute(StunMessage.AttrNonce));
            Assert.True(VerifyMessageIntegrity(encoded, LongTermKey(challengedRealm)));
        }
    }

    [Fact]
    public void IncompleteCredentialsLeaveProtectedRequestUnsigned()
    {
        var authenticator = new TurnLongTermAuthenticator();
        Assert.True(authenticator.Update(new PeerMeshConfig
        {
            IceUsername = Username,
            IceCredential = Credential,
        }));
        Assert.False(authenticator.CanAuthenticate);

        var request = StunMessage.Of(
            StunMessage.AllocateRequest,
            TransactionId(7),
            StunMessage.RequestedUdpTransportAttribute());
        var parsed = StunMessage.Parse(authenticator.Encode(request))!;

        Assert.Null(parsed.First(StunMessage.AttrMessageIntegrity));
        Assert.Null(parsed.First(StunMessage.AttrUsername));
    }

    private static TurnLongTermAuthenticator Authenticator()
    {
        var authenticator = new TurnLongTermAuthenticator();
        Assert.True(authenticator.Update(Config(Realm, Nonce)));
        Assert.True(authenticator.CanAuthenticate);
        return authenticator;
    }

    internal static PeerMeshConfig Config(string realm, string nonce) => new()
    {
        IceUsername = Username,
        IceCredential = Credential,
        IceRealm = realm,
        IceNonce = nonce,
    };

    internal static byte[] LongTermKey(string realm) =>
        MD5.HashData(Encoding.UTF8.GetBytes($"{Username}:{realm}:{Credential}"));

    internal static bool VerifyMessageIntegrity(byte[] packet, byte[] key)
    {
        var parsed = StunMessage.Parse(packet);
        var expected = parsed?.First(StunMessage.AttrMessageIntegrity)?.Value;
        if (expected is not { Length: 20 } || packet.Length < 24)
        {
            return false;
        }
        using var hmac = new HMACSHA1(key);
        var actual = hmac.ComputeHash(packet, 0, packet.Length - 24);
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    internal static byte[] TransactionId(int seed) =>
        Enumerable.Range(0, StunMessage.TransactionIdBytes).Select(index => (byte)(seed + index)).ToArray();
}
