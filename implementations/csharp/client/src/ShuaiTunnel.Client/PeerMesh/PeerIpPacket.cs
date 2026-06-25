using System.Buffers.Binary;
using System.Net;

namespace ShuaiTunnel.Client.PeerMesh;

internal static class PeerIpPacket
{
    private const byte ProtocolIcmp = 1;
    private const byte ProtocolTcp = 6;
    private const byte ProtocolUdp = 17;
    private const byte IcmpEchoReply = 0;
    private const byte IcmpEchoRequest = 8;

    public static string DestinationIPv4(ReadOnlySpan<byte> packet)
    {
        if (!IsIPv4(packet))
        {
            return "";
        }
        return new IPAddress(packet.Slice(16, 4)).ToString();
    }

    public static string SourceIPv4(ReadOnlySpan<byte> packet)
    {
        if (!IsIPv4(packet))
        {
            return "";
        }
        return new IPAddress(packet.Slice(12, 4)).ToString();
    }

    public static string FlowKey(ReadOnlySpan<byte> packet)
    {
        var source = SourceIPv4(packet);
        var target = DestinationIPv4(packet);
        if (source.Length == 0 || target.Length == 0)
        {
            return "";
        }
        var protocol = packet[9];
        var ihl = (packet[0] & 0x0f) * 4;
        var sourcePort = 0;
        var targetPort = 0;
        if ((protocol is ProtocolTcp or ProtocolUdp) && packet.Length >= ihl + 4)
        {
            sourcePort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl, 2));
            targetPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 2, 2));
        }
        return $"{source}:{sourcePort}->{target}:{targetPort}/{protocol}";
    }

    public static byte[]? IcmpEchoReplyFor(ReadOnlySpan<byte> packet, string? localVirtualIp)
    {
        if (!IsIcmpEchoRequestFor(packet, localVirtualIp))
        {
            return null;
        }
        var ihl = (packet[0] & 0x0f) * 4;
        var totalLength = TotalLength(packet);
        var reply = packet[..totalLength].ToArray();
        reply.AsSpan(16, 4).CopyTo(reply.AsSpan(12, 4));
        packet.Slice(12, 4).CopyTo(reply.AsSpan(16, 4));
        reply[8] = 64;
        reply[10] = 0;
        reply[11] = 0;

        reply[ihl] = IcmpEchoReply;
        reply[ihl + 1] = 0;
        reply[ihl + 2] = 0;
        reply[ihl + 3] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(ihl + 2, 2), Checksum(reply.AsSpan(ihl, totalLength - ihl)));
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(10, 2), Checksum(reply.AsSpan(0, ihl)));
        return reply;
    }

    private static bool IsIPv4(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20 || packet[0] >> 4 != 4)
        {
            return false;
        }
        var ihl = (packet[0] & 0x0f) * 4;
        return ihl >= 20 && packet.Length >= ihl;
    }

    private static bool IsIcmpEchoRequestFor(ReadOnlySpan<byte> packet, string? localVirtualIp)
    {
        if (DestinationIPv4(packet) != localVirtualIp)
        {
            return false;
        }
        var ihl = (packet[0] & 0x0f) * 4;
        var totalLength = TotalLength(packet);
        return totalLength >= ihl + 8
            && totalLength <= packet.Length
            && packet[9] == ProtocolIcmp
            && packet[ihl] == IcmpEchoRequest
            && packet[ihl + 1] == 0;
    }

    private static int TotalLength(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 4)
        {
            return 0;
        }
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        return totalLength > 0 && totalLength <= packet.Length ? totalLength : packet.Length;
    }

    internal static ushort Checksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        var index = 0;
        while (index + 1 < data.Length)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(index, 2));
            index += 2;
        }
        if (index < data.Length)
        {
            sum += (uint)data[index] << 8;
        }
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        return (ushort)~sum;
    }
}
