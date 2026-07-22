using System.Buffers.Binary;
using System.Text;

namespace ShuaiTunnel.Server.WebSockets;

internal static class PublicTransferRelayFrame
{
    public const int MaxWireBytes = 64 * 1024;
    public const byte AppTypeAck = 127;

    private const int RelayHeaderBytes = 14;
    private const int AppHeaderBytes = 72;
    private const int MaxPeerIdBytes = 512;
    private const uint MaxAppMessageBytes = 8 * 1024 * 1024;
    private const uint MaxChunkCount = 2048;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static PublicTransferRelayClientFrame DecodeClient(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < RelayHeaderBytes + AppHeaderBytes || frame.Length > MaxWireBytes
            || !frame[..4].SequenceEqual("STWR"u8) || frame[4] != 2 || frame[5] != 0)
        {
            throw Invalid();
        }
        var targetLength = BinaryPrimitives.ReadUInt16BigEndian(frame[6..8]);
        var sourceLength = BinaryPrimitives.ReadUInt16BigEndian(frame[8..10]);
        var payloadLength = BinaryPrimitives.ReadUInt32BigEndian(frame[10..14]);
        if (targetLength is 0 or > MaxPeerIdBytes || sourceLength != 0
            || payloadLength < AppHeaderBytes
            || RelayHeaderBytes + (ulong)targetLength + payloadLength != (ulong)frame.Length)
        {
            throw Invalid();
        }
        string targetPeerId;
        try
        {
            targetPeerId = StrictUtf8.GetString(frame.Slice(RelayHeaderBytes, targetLength));
        }
        catch (DecoderFallbackException)
        {
            throw Invalid();
        }
        if (string.IsNullOrWhiteSpace(targetPeerId) || targetPeerId.Any(char.IsControl))
        {
            throw Invalid();
        }
        var appFrame = frame[(RelayHeaderBytes + targetLength)..].ToArray();
        var appType = ValidateAppFrame(appFrame);
        return new PublicTransferRelayClientFrame(targetPeerId, appType, appFrame);
    }

    public static byte[] EncodeServer(string targetPeerId, string sourcePeerId,
        ReadOnlySpan<byte> appFrame)
    {
        var target = StrictUtf8.GetBytes(targetPeerId);
        var source = StrictUtf8.GetBytes(sourcePeerId);
        if (target.Length is 0 or > MaxPeerIdBytes || source.Length is 0 or > MaxPeerIdBytes)
        {
            throw Invalid();
        }
        _ = ValidateAppFrame(appFrame);
        var wireLength = RelayHeaderBytes + target.Length + source.Length + appFrame.Length;
        if (wireLength > MaxWireBytes)
        {
            throw Invalid();
        }
        var result = new byte[wireLength];
        "STWR"u8.CopyTo(result);
        result[4] = 2;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6, 2), checked((ushort)target.Length));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8, 2), checked((ushort)source.Length));
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(10, 4), checked((uint)appFrame.Length));
        var offset = RelayHeaderBytes;
        target.CopyTo(result, offset);
        offset += target.Length;
        source.CopyTo(result, offset);
        offset += source.Length;
        appFrame.CopyTo(result.AsSpan(offset));
        return result;
    }

    private static byte ValidateAppFrame(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < AppHeaderBytes || !frame[..4].SequenceEqual("STAP"u8) || frame[4] != 2)
        {
            throw Invalid();
        }
        var appType = frame[5];
        if (appType is not (1 or 2 or 3 or AppTypeAck))
        {
            throw Invalid();
        }
        var flags = BinaryPrimitives.ReadUInt16BigEndian(frame[6..8]);
        if ((flags & ~1) != 0 || appType == AppTypeAck && flags != 0)
        {
            throw Invalid();
        }
        var chunkIndex = BinaryPrimitives.ReadUInt32BigEndian(frame[24..28]);
        var chunkCount = BinaryPrimitives.ReadUInt32BigEndian(frame[28..32]);
        var totalLength = BinaryPrimitives.ReadUInt32BigEndian(frame[32..36]);
        var payloadLength = BinaryPrimitives.ReadUInt32BigEndian(frame[36..40]);
        if (chunkCount is 0 or > MaxChunkCount || chunkIndex >= chunkCount
            || totalLength > MaxAppMessageBytes || payloadLength > totalLength
            || AppHeaderBytes + (ulong)payloadLength != (ulong)frame.Length)
        {
            throw Invalid();
        }
        return appType;
    }

    private static ArgumentException Invalid() =>
        new("invalid public transfer relay frame");
}

internal sealed record PublicTransferRelayClientFrame(string TargetPeerId, byte AppType,
    byte[] AppFrame);
