using System.Buffers.Binary;
using System.Net;

namespace Specus.Client.PeerMesh;

internal static class PeerIpPacket
{
    private const byte ProtocolIcmp = 1;
    private const byte ProtocolTcp = 6;
    private const byte ProtocolUdp = 17;
    private const byte IcmpEchoReply = 0;
    private const byte IcmpEchoRequest = 8;
    private const byte IcmpDestinationUnreachable = 3;
    private const byte IcmpFragmentationNeeded = 4;

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

    public static bool MatchesAuthenticatedEndpoints(ReadOnlySpan<byte> packet, string? peerVirtualIp,
        string? localVirtualIp) =>
        !string.IsNullOrWhiteSpace(peerVirtualIp)
        && !string.IsNullOrWhiteSpace(localVirtualIp)
        && string.Equals(SourceIPv4(packet), peerVirtualIp, StringComparison.Ordinal)
        && string.Equals(DestinationIPv4(packet), localVirtualIp, StringComparison.Ordinal);

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

    public static byte[] ClampTcpMss(byte[] packet, int pathMtu)
    {
        ReadOnlySpan<byte> view = packet;
        if (!IsIPv4(view) || view[9] != ProtocolTcp)
        {
            return packet;
        }
        var ipHeaderLength = (view[0] & 0x0f) * 4;
        var totalLength = TotalLength(view);
        if (totalLength < ipHeaderLength + 20 || (view[ipHeaderLength + 13] & 0x02) == 0)
        {
            return packet;
        }
        var tcpHeaderLength = (view[ipHeaderLength + 12] >> 4) * 4;
        if (tcpHeaderLength < 20 || totalLength < ipHeaderLength + tcpHeaderLength)
        {
            return packet;
        }
        var maxMss = Math.Max(536, pathMtu - ipHeaderLength - 20);
        for (var cursor = ipHeaderLength + 20; cursor < ipHeaderLength + tcpHeaderLength;)
        {
            var kind = view[cursor];
            if (kind == 0)
            {
                break;
            }
            if (kind == 1)
            {
                cursor++;
                continue;
            }
            if (cursor + 1 >= ipHeaderLength + tcpHeaderLength)
            {
                break;
            }
            var optionLength = view[cursor + 1];
            if (optionLength < 2 || cursor + optionLength > ipHeaderLength + tcpHeaderLength)
            {
                break;
            }
            if (kind == 2 && optionLength == 4)
            {
                var advertised = BinaryPrimitives.ReadUInt16BigEndian(view.Slice(cursor + 2, 2));
                if (advertised <= maxMss)
                {
                    return packet;
                }
                var clamped = packet.ToArray();
                BinaryPrimitives.WriteUInt16BigEndian(clamped.AsSpan(cursor + 2, 2), checked((ushort)maxMss));
                clamped[ipHeaderLength + 16] = 0;
                clamped[ipHeaderLength + 17] = 0;
                BinaryPrimitives.WriteUInt16BigEndian(
                    clamped.AsSpan(ipHeaderLength + 16, 2),
                    TcpChecksum(clamped, ipHeaderLength, totalLength - ipHeaderLength));
                return clamped;
            }
            cursor += optionLength;
        }
        return packet;
    }

    public static byte[]? IcmpFragmentationNeededFor(ReadOnlySpan<byte> packet, int pathMtu)
    {
        if (!IsIPv4(packet))
        {
            return null;
        }
        var originalHeaderLength = (packet[0] & 0x0f) * 4;
        var originalLength = TotalLength(packet);
        var quotedLength = Math.Min(originalLength, originalHeaderLength + 8);
        var response = new byte[20 + 8 + quotedLength];
        response[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), checked((ushort)response.Length));
        response[8] = 64;
        response[9] = ProtocolIcmp;
        packet.Slice(16, 4).CopyTo(response.AsSpan(12, 4));
        packet.Slice(12, 4).CopyTo(response.AsSpan(16, 4));
        response[20] = IcmpDestinationUnreachable;
        response[21] = IcmpFragmentationNeeded;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(26, 2), checked((ushort)pathMtu));
        packet[..quotedLength].CopyTo(response.AsSpan(28));
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(22, 2), Checksum(response.AsSpan(20)));
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10, 2), Checksum(response.AsSpan(0, 20)));
        return response;
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

    private static ushort TcpChecksum(ReadOnlySpan<byte> packet, int tcpOffset, int tcpLength)
    {
        uint sum = 0;
        for (var index = 12; index < 20; index += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(index, 2));
        }
        sum += ProtocolTcp;
        sum += checked((uint)tcpLength);
        var segment = packet.Slice(tcpOffset, tcpLength);
        var cursor = 0;
        while (cursor + 1 < segment.Length)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(segment.Slice(cursor, 2));
            cursor += 2;
        }
        if (cursor < segment.Length)
        {
            sum += (uint)segment[cursor] << 8;
        }
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        return (ushort)~sum;
    }
}
