using System.Buffers.Binary;

namespace ShuaiTunnel.Server.PeerMesh;

internal sealed record PeerDataFrameHeader(
    long SessionId,
    long FromClientId,
    long ToClientId,
    long Sequence)
{
    private const uint Magic = 0x53504d31;
    private const byte Version = 1;
    private const byte TypeData = 1;
    private const int HeaderBytes = 50;

    public static PeerDataFrameHeader? Parse(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < HeaderBytes || BinaryPrimitives.ReadUInt32BigEndian(frame[..4]) != Magic)
        {
            return null;
        }
        if (frame[4] != Version || frame[5] != TypeData)
        {
            return null;
        }
        return new PeerDataFrameHeader(
            (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(6, 8)),
            (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(14, 8)),
            (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(22, 8)),
            (long)BinaryPrimitives.ReadUInt64BigEndian(frame.Slice(30, 8)));
    }
}
