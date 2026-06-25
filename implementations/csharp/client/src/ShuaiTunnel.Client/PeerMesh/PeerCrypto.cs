using System.Security.Cryptography;
using System.Text;

namespace ShuaiTunnel.Client.PeerMesh;

internal static class PeerCrypto
{
    private static readonly byte[] X25519PublicKeyDerPrefix =
    [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    ];

    private static readonly byte[] X25519PrivateKeyDerPrefix =
    [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03,
        0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
    ];

    public static ECDiffieHellman CreateX25519()
    {
        return ECDiffieHellman.Create(ECCurve.CreateFromOid(new Oid("1.3.101.110", "X25519")));
    }

    public static byte[] DeriveAes256Key(
        string localPrivateKeyBase64,
        string remotePublicKeyBase64,
        long sessionId,
        string? sessionToken,
        long localClientId,
        long remoteClientId)
    {
        var localPrivateKey = DecodePrivateKey(localPrivateKeyBase64);
        var remotePublicKey = DecodePublicKey(remotePublicKeyBase64);
        using var local = ECDiffieHellman.Create();
        local.ImportPkcs8PrivateKey(localPrivateKey, out _);
        using var remote = ECDiffieHellman.Create();
        remote.ImportSubjectPublicKeyInfo(remotePublicKey, out _);
        var sharedSecret = local.DeriveRawSecretAgreement(remote.PublicKey);
        var min = Math.Min(localClientId, remoteClientId);
        var max = Math.Max(localClientId, remoteClientId);
        var salt = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"shuai-peer-mesh\n{sessionId}\n{sessionToken ?? ""}\n{min}\n{max}"));
        var prk = HmacSha256(salt, sharedSecret);
        return HkdfExpandSha256(prk, Encoding.UTF8.GetBytes("shuai-peer-mesh/aes-gcm/v1"), 32);
    }

    internal static byte[] DecodePublicKey(string value)
    {
        var decoded = Convert.FromBase64String(value);
        if (decoded.Length == 32)
        {
            return [.. X25519PublicKeyDerPrefix, .. decoded];
        }
        if (decoded.Length == X25519PublicKeyDerPrefix.Length + 32
            && decoded.AsSpan(0, X25519PublicKeyDerPrefix.Length).SequenceEqual(X25519PublicKeyDerPrefix))
        {
            return decoded;
        }
        throw new CryptographicException("unsupported peer public key format");
    }

    internal static byte[] DecodePrivateKey(string value)
    {
        var decoded = Convert.FromBase64String(value);
        if (decoded.Length == 32)
        {
            return [.. X25519PrivateKeyDerPrefix, .. decoded];
        }
        if (decoded.Length == X25519PrivateKeyDerPrefix.Length + 32
            && decoded.AsSpan(0, X25519PrivateKeyDerPrefix.Length).SequenceEqual(X25519PrivateKeyDerPrefix))
        {
            return decoded;
        }
        return decoded;
    }

    private static byte[] HkdfExpandSha256(byte[] prk, byte[] info, int length)
    {
        var result = new byte[length];
        var previous = Array.Empty<byte>();
        var copied = 0;
        byte counter = 1;
        while (copied < length)
        {
            var input = new byte[previous.Length + info.Length + 1];
            previous.CopyTo(input, 0);
            info.CopyTo(input, previous.Length);
            input[^1] = counter++;
            previous = HmacSha256(prk, input);
            var toCopy = Math.Min(previous.Length, length - copied);
            previous.AsSpan(0, toCopy).CopyTo(result.AsSpan(copied));
            copied += toCopy;
        }
        return result;
    }

    private static byte[] HmacSha256(byte[] key, byte[] data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }
}
