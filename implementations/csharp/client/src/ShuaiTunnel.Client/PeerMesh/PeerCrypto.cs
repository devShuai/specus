using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace ShuaiTunnel.Client.PeerMesh;

internal static class PeerCrypto
{
    private const int X25519KeySize = 32;
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;
    private static readonly BigInteger A24 = new(121665);

    private static readonly byte[] X25519PublicKeyDerPrefix =
    [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    ];

    private static readonly byte[] X25519PrivateKeyDerPrefix =
    [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03,
        0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
    ];

    public static PeerKeyMaterial GenerateKeyMaterial()
    {
        var privateKey = RandomNumberGenerator.GetBytes(X25519KeySize);
        var publicKey = X25519Raw(privateKey, BasePoint());
        var publicDer = X25519PublicKeyDerPrefix.Concat(publicKey).ToArray();
        var privateDer = X25519PrivateKeyDerPrefix.Concat(privateKey).ToArray();
        return new PeerKeyMaterial(
            Convert.ToBase64String(publicDer),
            Convert.ToBase64String(privateDer));
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
        var sharedSecret = X25519Raw(localPrivateKey, remotePublicKey);
        if (IsAllZero(sharedSecret))
        {
            throw new CryptographicException("X25519 shared secret is all zero");
        }
        var min = Math.Min(localClientId, remoteClientId);
        var max = Math.Max(localClientId, remoteClientId);
        var salt = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"shuai-peer-mesh\n{sessionId}\n{sessionToken ?? ""}\n{min}\n{max}"));
        var prk = HmacSha256(salt, sharedSecret);
        return HkdfExpandSha256(prk, Encoding.UTF8.GetBytes("shuai-peer-mesh/aes-gcm/v1"), 32);
    }

    internal static byte[] X25519Raw(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate)
    {
        if (scalar.Length != X25519KeySize || uCoordinate.Length != X25519KeySize)
        {
            throw new CryptographicException("X25519 keys must be 32 bytes");
        }

        Span<byte> k = stackalloc byte[X25519KeySize];
        scalar.CopyTo(k);
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;

        Span<byte> u = stackalloc byte[X25519KeySize];
        uCoordinate.CopyTo(u);
        u[31] &= 127;

        var x1 = FromLittleEndian(u);
        var x2 = BigInteger.One;
        var z2 = BigInteger.Zero;
        var x3 = x1;
        var z3 = BigInteger.One;
        var swap = 0;

        for (var t = 254; t >= 0; t--)
        {
            var kt = (k[t >> 3] >> (t & 7)) & 1;
            swap ^= kt;
            if (swap != 0)
            {
                Swap(ref x2, ref x3);
                Swap(ref z2, ref z3);
            }
            swap = kt;

            var a = Mod(x2 + z2);
            var aa = Mod(a * a);
            var b = Mod(x2 - z2);
            var bb = Mod(b * b);
            var e = Mod(aa - bb);
            var c = Mod(x3 + z3);
            var d = Mod(x3 - z3);
            var da = Mod(d * a);
            var cb = Mod(c * b);
            x3 = Mod((da + cb) * (da + cb));
            z3 = Mod(x1 * Mod((da - cb) * (da - cb)));
            x2 = Mod(aa * bb);
            z2 = Mod(e * Mod(aa + A24 * e));
        }

        if (swap != 0)
        {
            Swap(ref x2, ref x3);
            Swap(ref z2, ref z3);
        }

        var result = ToLittleEndian32(Mod(x2 * ModInverse(z2)));
        CryptographicOperations.ZeroMemory(k);
        CryptographicOperations.ZeroMemory(u);
        return result;
    }

    internal static byte[] DecodePublicKey(string value)
    {
        var decoded = Convert.FromBase64String(value);
        if (decoded.Length == X25519KeySize)
        {
            return decoded;
        }
        if (decoded.Length == X25519PublicKeyDerPrefix.Length + X25519KeySize
            && decoded.AsSpan(0, X25519PublicKeyDerPrefix.Length).SequenceEqual(X25519PublicKeyDerPrefix))
        {
            return decoded[X25519PublicKeyDerPrefix.Length..];
        }
        throw new CryptographicException("unsupported peer public key format");
    }

    internal static byte[] DecodePrivateKey(string value)
    {
        var decoded = Convert.FromBase64String(value);
        if (decoded.Length == X25519KeySize)
        {
            return decoded;
        }
        if (decoded.Length == X25519PrivateKeyDerPrefix.Length + X25519KeySize
            && decoded.AsSpan(0, X25519PrivateKeyDerPrefix.Length).SequenceEqual(X25519PrivateKeyDerPrefix))
        {
            return decoded[X25519PrivateKeyDerPrefix.Length..];
        }
        throw new CryptographicException("unsupported peer private key format");
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

    private static byte[] BasePoint()
    {
        var result = new byte[X25519KeySize];
        result[0] = 9;
        return result;
    }

    private static BigInteger FromLittleEndian(ReadOnlySpan<byte> value) =>
        new(value, isUnsigned: true, isBigEndian: false);

    private static byte[] ToLittleEndian32(BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        if (bytes.Length > X25519KeySize)
        {
            throw new CryptographicException("X25519 field element overflow");
        }
        var result = new byte[X25519KeySize];
        bytes.AsSpan().CopyTo(result);
        return result;
    }

    private static BigInteger Mod(BigInteger value)
    {
        value %= P;
        return value.Sign < 0 ? value + P : value;
    }

    private static BigInteger ModInverse(BigInteger value) => BigInteger.ModPow(value, P - 2, P);

    private static void Swap(ref BigInteger left, ref BigInteger right) => (left, right) = (right, left);

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }
        return aggregate == 0;
    }
}
