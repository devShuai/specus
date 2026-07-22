using System.Buffers.Binary;

namespace ShuaiTunnel.Client.PeerMesh;

internal sealed record TurnChannelData(ushort Channel, byte[] Payload)
{
    internal const ushort MinChannel = 0x4000;
    internal const ushort MaxChannel = 0x7fff;

    internal static bool LooksLike(ReadOnlySpan<byte> packet) =>
        packet.Length >= 4 && BinaryPrimitives.ReadUInt16BigEndian(packet[..2]) is >= MinChannel and <= MaxChannel;

    internal static TurnChannelData? Parse(ReadOnlySpan<byte> packet)
    {
        if (!LooksLike(packet))
        {
            return null;
        }
        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        var end = 4 + payloadLength;
        if (end > packet.Length || packet.Length - end > 3 || packet[end..].IndexOfAnyExcept((byte)0) >= 0)
        {
            return null;
        }
        return new TurnChannelData(BinaryPrimitives.ReadUInt16BigEndian(packet[..2]), packet[4..end].ToArray());
    }

    internal static byte[] Encode(ushort channel, ReadOnlySpan<byte> payload)
    {
        if (channel is < MinChannel or > MaxChannel)
        {
            throw new ArgumentOutOfRangeException(nameof(channel));
        }
        if (payload.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(payload));
        }
        var padding = (4 - payload.Length % 4) % 4;
        var packet = new byte[4 + payload.Length + padding];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), channel);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), checked((ushort)payload.Length));
        payload.CopyTo(packet.AsSpan(4));
        return packet;
    }
}
