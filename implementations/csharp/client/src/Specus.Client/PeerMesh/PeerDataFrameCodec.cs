using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Specus.Client.PeerMesh;

internal static class PeerDataFrameCodec
{
    public const uint Magic = 0x53504d32; // SPM2
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    internal const int HeaderBytes = 4 + 8 * 2;
    private const int MinFrameBytes = HeaderBytes + TagBytes;
    private const int MaxFrameBytes = 65535;

    public static byte[] Encode(
        byte[] aesKey,
        long sessionId,
        long fromClientId,
        long toClientId,
        string senderKeyEpoch,
        long sequence,
        ReadOnlySpan<byte> payload)
    {
        using var codec = CreateTrafficCodec(aesKey, sessionId, fromClientId, toClientId, senderKeyEpoch);
        return codec.Encode(sessionId, sequence, payload);
    }

    public static PeerDataFrame Decode(
        byte[] aesKey,
        long expectedFromClientId,
        long expectedToClientId,
        string senderKeyEpoch,
        ReadOnlySpan<byte> frame)
    {
        if (aesKey.Length != 32
            || frame.Length < MinFrameBytes
            || frame.Length > MaxFrameBytes
            || BinaryPrimitives.ReadUInt32BigEndian(frame[..4]) != Magic)
        {
            throw new CryptographicException("invalid SPM2 peer data frame");
        }
        var sessionId = (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(4, 8));
        var sequence = (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(12, 8));
        if (sessionId <= 0 || expectedFromClientId <= 0 || expectedToClientId <= 0
            || expectedFromClientId == expectedToClientId || sequence <= 0)
        {
            throw new CryptographicException("invalid SPM2 session, direction, or sequence");
        }

        using var codec = CreateTrafficCodec(
            aesKey, sessionId, expectedFromClientId, expectedToClientId, senderKeyEpoch);
        return codec.Decode(sessionId, frame);
    }

    public static bool LooksLikeDataFrame(ReadOnlySpan<byte> value) =>
        value.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(value[..4]) == Magic;

    public static long? SessionId(ReadOnlySpan<byte> value) =>
        value.Length is >= MinFrameBytes and <= MaxFrameBytes && LooksLikeDataFrame(value)
            ? (long)BinaryPrimitives.ReadUInt64BigEndian(value.Slice(4, 8))
            : null;

    internal static TrafficCodec CreateTrafficCodec(
        byte[] aesKey,
        long sessionId,
        long fromClientId,
        long toClientId,
        string senderKeyEpoch)
    {
        if (aesKey.Length != 32 || sessionId <= 0 || fromClientId <= 0 || toClientId <= 0
            || fromClientId == toClientId)
        {
            throw new CryptographicException("invalid SPM2 key, session, or direction");
        }
        if (string.IsNullOrWhiteSpace(senderKeyEpoch))
        {
            throw new CryptographicException("SPM2 traffic key requires the sender key epoch");
        }
        var (trafficKey, noncePrefix) = DeriveTrafficMaterial(
            aesKey, sessionId, fromClientId, toClientId, senderKeyEpoch);
        return new TrafficCodec(trafficKey, noncePrefix);
    }

    /// <summary>
    /// Derives the one-way traffic key. <paramref name="senderKeyEpoch"/> is the sender's
    /// per-process random epoch and is mandatory: sessionId/token are reused within the server
    /// session TTL and X25519 keys are persisted on disk, so without a fresh epoch a client
    /// restart would replay the same nonce space under the same AES-GCM key.
    /// </summary>
    private static (byte[] Key, uint NoncePrefix) DeriveTrafficMaterial(
        byte[] aesKey,
        long sessionId,
        long fromClientId,
        long toClientId,
        string senderKeyEpoch)
    {
        Span<byte> salt = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(salt, (ulong)sessionId);
        var prk = HMACSHA256.HashData(salt, aesKey);
        var infoText = $"specus-peer-mesh/spm2/aes-gcm\n{sessionId}\n{fromClientId}\n{toClientId}\n{senderKeyEpoch}";
        var info = Encoding.ASCII.GetBytes(infoText);
        var material = HkdfExpand(prk, info, 36);
        return (material[..32], BinaryPrimitives.ReadUInt32BigEndian(material.AsSpan(32, 4)));
    }

    private static byte[] HkdfExpand(byte[] prk, byte[] info, int length)
    {
        var result = new byte[length];
        var previous = Array.Empty<byte>();
        var offset = 0;
        byte counter = 1;
        while (offset < result.Length)
        {
            var input = new byte[previous.Length + info.Length + 1];
            previous.CopyTo(input, 0);
            info.CopyTo(input, previous.Length);
            input[^1] = counter++;
            previous = HMACSHA256.HashData(prk, input);
            var count = Math.Min(previous.Length, result.Length - offset);
            previous.AsSpan(0, count).CopyTo(result.AsSpan(offset));
            offset += count;
        }
        return result;
    }

    private static void WriteNonce(Span<byte> nonce, uint prefix, ulong sequence)
    {
        BinaryPrimitives.WriteUInt32BigEndian(nonce[..4], prefix);
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], sequence);
    }

    internal sealed class TrafficCodec(byte[] trafficKey, uint noncePrefix) : IDisposable
    {
        private readonly AesGcm _gcm = new(trafficKey, TagBytes);
        private readonly object _sync = new();

        internal byte[] Encode(long sessionId, long sequence, ReadOnlySpan<byte> payload)
        {
            if (sessionId <= 0 || sequence <= 0)
            {
                throw new CryptographicException("invalid SPM2 session or sequence");
            }
            if (HeaderBytes + payload.Length + TagBytes > MaxFrameBytes)
            {
                throw new CryptographicException("SPM2 peer data frame is too large");
            }
            var frame = new byte[HeaderBytes + payload.Length + TagBytes];
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(0, 4), Magic);
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(4, 8), (ulong)sessionId);
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(12, 8), (ulong)sequence);
            Span<byte> nonce = stackalloc byte[NonceBytes];
            WriteNonce(nonce, noncePrefix, (ulong)sequence);
            lock (_sync)
            {
                _gcm.Encrypt(
                    nonce,
                    payload,
                    frame.AsSpan(HeaderBytes, payload.Length),
                    frame.AsSpan(HeaderBytes + payload.Length, TagBytes),
                    frame.AsSpan(0, HeaderBytes));
            }
            return frame;
        }

        internal PeerDataFrame Decode(long expectedSessionId, ReadOnlySpan<byte> frame)
        {
            if (frame.Length < MinFrameBytes
                || frame.Length > MaxFrameBytes
                || BinaryPrimitives.ReadUInt32BigEndian(frame[..4]) != Magic)
            {
                throw new CryptographicException("invalid SPM2 peer data frame");
            }
            var sessionId = (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(4, 8));
            var sequence = (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(12, 8));
            if (sessionId <= 0 || sessionId != expectedSessionId || sequence <= 0)
            {
                throw new CryptographicException("invalid SPM2 session or sequence");
            }
            Span<byte> nonce = stackalloc byte[NonceBytes];
            WriteNonce(nonce, noncePrefix, (ulong)sequence);
            var payloadLength = frame.Length - HeaderBytes - TagBytes;
            var payload = new byte[payloadLength];
            lock (_sync)
            {
                _gcm.Decrypt(
                    nonce,
                    frame.Slice(HeaderBytes, payloadLength),
                    frame.Slice(HeaderBytes + payloadLength, TagBytes),
                    payload,
                    frame[..HeaderBytes]);
            }
            return new PeerDataFrame(sessionId, sequence, payload);
        }

        public void Dispose()
        {
            lock (_sync)
            {
                _gcm.Dispose();
            }
        }
    }
}

internal sealed record PeerDataFrame(
    long SessionId,
    long Sequence,
    byte[] Payload);
