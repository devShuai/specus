using System.Buffers.Binary;

namespace ShuaiTunnel.Server.PeerMesh;

internal sealed record PeerDataFrameHeader(
    long SessionId,
    long Sequence)
{
    private const uint Magic = 0x53504d32; // SPM2
    private const int HeaderBytes = 20;
    private const int TagBytes = 16;
    private const int MaxFrameBytes = 65535;

    public static bool LooksLikeDataFrame(ReadOnlySpan<byte> frame) =>
        frame.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(frame[..4]) == Magic;

    public static PeerDataFrameHeader? Parse(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < HeaderBytes + TagBytes || frame.Length > MaxFrameBytes || !LooksLikeDataFrame(frame))
        {
            return null;
        }
        var sequence = (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(12, 8));
        return sequence > 0
            ? new PeerDataFrameHeader(
                (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(4, 8)),
                sequence)
            : null;
    }
}
