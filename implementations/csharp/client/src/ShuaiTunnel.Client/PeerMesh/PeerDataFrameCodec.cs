using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ShuaiTunnel.Client.PeerMesh;

internal static class PeerDataFrameCodec
{
    public const uint Magic = 0x53504d31;
    public const byte Version = 1;
    public const byte TypeData = 1;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int AadBytes = 4 + 2 + 8 * 4 + NonceBytes;
    private const int MinFrameBytes = AadBytes + 4 + TagBytes;
    private const int MaxFrameBytes = 65535;

    public static byte[] Encode(
        byte[] aesKey,
        long sessionId,
        long fromClientId,
        long toClientId,
        long sequence,
        ReadOnlySpan<byte> payload)
    {
        if (aesKey.Length != 32)
        {
            throw new CryptographicException("peer data frame AES key must be 32 bytes");
        }
        if (sequence <= 0)
        {
            throw new CryptographicException("peer data frame sequence must be positive");
        }
        Span<byte> nonce = stackalloc byte[NonceBytes];
        RandomNumberGenerator.Fill(nonce);
        var aad = new byte[AadBytes];
        WriteHeader(aad, sessionId, fromClientId, toClientId, sequence, nonce);
        var ciphertext = new byte[payload.Length];
        var tag = new byte[TagBytes];
        using var gcm = new AesGcm(aesKey, TagBytes);
        gcm.Encrypt(nonce, payload, ciphertext, tag, aad);
        var cipherLength = ciphertext.Length + tag.Length;
        if (AadBytes + 4 + cipherLength > MaxFrameBytes)
        {
            throw new CryptographicException("peer data frame is too large");
        }
        var frame = new byte[AadBytes + 4 + cipherLength];
        aad.CopyTo(frame, 0);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(AadBytes, 4), (uint)cipherLength);
        ciphertext.CopyTo(frame.AsSpan(AadBytes + 4));
        tag.CopyTo(frame.AsSpan(AadBytes + 4 + ciphertext.Length));
        return frame;
    }

    public static PeerDataFrame Decode(byte[] aesKey, ReadOnlySpan<byte> frame)
    {
        if (aesKey.Length != 32)
        {
            throw new CryptographicException("peer data frame AES key must be 32 bytes");
        }
        if (frame.Length < MinFrameBytes)
        {
            throw new CryptographicException("peer data frame is too short");
        }
        if (!LooksLikeDataFrame(frame))
        {
            throw new CryptographicException("invalid peer data frame magic");
        }
        if (frame[4] != Version || frame[5] != TypeData)
        {
            throw new CryptographicException("unsupported peer data frame version/type");
        }
        var cipherLength = (int)BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(AadBytes, 4));
        if (cipherLength < TagBytes || frame.Length != AadBytes + 4 + cipherLength)
        {
            throw new CryptographicException("invalid peer data frame ciphertext length");
        }
        var ciphertextLength = cipherLength - TagBytes;
        var payload = new byte[ciphertextLength];
        var ciphertext = frame.Slice(AadBytes + 4, ciphertextLength);
        var tag = frame.Slice(AadBytes + 4 + ciphertextLength, TagBytes);
        var nonce = frame.Slice(38, NonceBytes);
        using var gcm = new AesGcm(aesKey, TagBytes);
        gcm.Decrypt(nonce, ciphertext, tag, payload, frame[..AadBytes]);
        return new PeerDataFrame(
            (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(6, 8)),
            (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(14, 8)),
            (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(22, 8)),
            (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(30, 8)),
            payload);
    }

    public static bool LooksLikeDataFrame(ReadOnlySpan<byte> value)
    {
        return value.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(value[..4]) == Magic;
    }

    private static void WriteHeader(
        Span<byte> header,
        long sessionId,
        long fromClientId,
        long toClientId,
        long sequence,
        ReadOnlySpan<byte> nonce)
    {
        BinaryPrimitives.WriteUInt32BigEndian(header[..4], Magic);
        header[4] = Version;
        header[5] = TypeData;
        BinaryPrimitives.WriteUInt64BigEndian(header.Slice(6, 8), (ulong)sessionId);
        BinaryPrimitives.WriteUInt64BigEndian(header.Slice(14, 8), (ulong)fromClientId);
        BinaryPrimitives.WriteUInt64BigEndian(header.Slice(22, 8), (ulong)toClientId);
        BinaryPrimitives.WriteUInt64BigEndian(header.Slice(30, 8), (ulong)sequence);
        nonce.CopyTo(header.Slice(38, NonceBytes));
    }
}

internal sealed record PeerDataFrame(
    long SessionId,
    long FromClientId,
    long ToClientId,
    long Sequence,
    byte[] Payload);
