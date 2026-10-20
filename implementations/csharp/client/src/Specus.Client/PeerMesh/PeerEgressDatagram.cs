using System.Buffers.Binary;

namespace Specus.Client.PeerMesh;

/// <summary>
/// UDP datagram encoding and decoding for the egress user-space stack.
/// </summary>
/// <remarks>
/// The counterpart of <see cref="PeerEgressSegment"/>. The egress terminates UDP in user space for
/// the same reason it terminates TCP there: no NAT table, no routing entry and no elevated
/// privileges, which is what lets an ordinary desktop act as an egress.
///
/// <para>QUIC needs nothing of its own. It rides on UDP, so it is carried by exactly this path as
/// one long-lived session per four-tuple, kept alive by its own traffic rather than by anything
/// here.</para>
/// </remarks>
internal static class PeerEgressDatagram
{
    public const int UdpHeaderBytes = 8;
    public const byte Ipv4ProtocolUdp = 17;

    /// <summary>
    /// The largest payload an IPv4 datagram can carry: 65535 less the minimum IPv4 header and the
    /// UDP header. Anything claiming more is malformed, not merely large.
    /// </summary>
    public const int MaxPayload = 65535 - PeerEgressSegment.Ipv4MinHeaderBytes - UdpHeaderBytes;

    /// <summary>
    /// One parsed UDP datagram together with the addresses that carried it: the IPv4 ones, or, when
    /// <see cref="Ipv6"/> is set, the IPv6 ones with the IPv4 fields left zero.
    /// </summary>
    internal sealed record Datagram(
        uint SourceIp,
        uint DestinationIp,
        ushort SourcePort,
        ushort DestinationPort,
        byte[] Payload,
        bool Ipv6 = false,
        UInt128 SourceIp6 = default,
        UInt128 DestinationIp6 = default);

    /// <summary>
    /// Reads an IPv4 packet carrying UDP, or returns null for anything it cannot fully validate.
    /// </summary>
    /// <remarks>
    /// Like the TCP parser it refuses rather than returning a best-effort result: a datagram we
    /// cannot trust must not open a session or reach a real socket.
    /// </remarks>
    public static Datagram? Parse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < PeerEgressSegment.Ipv4MinHeaderBytes)
        {
            return null;
        }
        if ((packet[0] >> 4) != 4 || packet[9] != Ipv4ProtocolUdp)
        {
            return null;
        }
        var ihl = (packet[0] & 0x0F) * 4;
        int total = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        if (ihl < PeerEgressSegment.Ipv4MinHeaderBytes
            || total < ihl + UdpHeaderBytes
            || total > packet.Length)
        {
            return null;
        }
        int length = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 4, 2));
        // The UDP length must describe exactly the bytes IPv4 delivered. Accepting a shorter one
        // would let a sender smuggle trailing bytes past us, which is why the frame layer refuses
        // trailing bytes too.
        if (length != total - ihl || length > UdpHeaderBytes + MaxPayload)
        {
            return null;
        }
        // A zero checksum means the sender did not compute one, which IPv4 permits. Present means
        // it must be right.
        if (BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 6, 2)) != 0
            && UdpChecksum(packet[..total], ihl, length) != 0)
        {
            return null;
        }

        return new Datagram(
            BinaryPrimitives.ReadUInt32BigEndian(packet[12..16]),
            BinaryPrimitives.ReadUInt32BigEndian(packet[16..20]),
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl, 2)),
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 2, 2)),
            packet[(ihl + UdpHeaderBytes)..total].ToArray());
    }

    /// <summary>
    /// Reads an IPv6 packet whose next header is UDP.
    /// </summary>
    /// <remarks>
    /// A zero checksum is refused rather than read as "none": IPv4 lets a sender leave it out, IPv6
    /// does not (RFC 8200 8.1), because there is no header checksum underneath to catch a damaged
    /// address.
    /// </remarks>
    public static Datagram? Parse6(ReadOnlySpan<byte> packet)
    {
        if (!PeerEgressIpv6.TryPayload(packet, Ipv4ProtocolUdp, out var udp) || udp.Length < UdpHeaderBytes)
        {
            return null;
        }
        if (BinaryPrimitives.ReadUInt16BigEndian(udp[4..6]) != udp.Length)
        {
            return null;
        }
        var source = PeerEgressIpv6.SourceOf(packet);
        var destination = PeerEgressIpv6.DestinationOf(packet);
        if (BinaryPrimitives.ReadUInt16BigEndian(udp[6..8]) == 0
            || PeerEgressIpv6.Checksum(source, destination, Ipv4ProtocolUdp, udp) != 0)
        {
            return null;
        }
        return new Datagram(
            0, 0,
            BinaryPrimitives.ReadUInt16BigEndian(udp[0..2]),
            BinaryPrimitives.ReadUInt16BigEndian(udp[2..4]),
            udp[UdpHeaderBytes..].ToArray(),
            Ipv6: true, SourceIp6: source, DestinationIp6: destination);
    }

    /// <summary>
    /// Renders a datagram as a complete IPv4 packet, or IPv6 packet when the datagram is IPv6,
    /// checksums included.
    /// </summary>
    public static byte[] Build(Datagram datagram)
    {
        var length = UdpHeaderBytes + datagram.Payload.Length;
        if (datagram.Ipv6)
        {
            var packet6 = new byte[PeerEgressIpv6.HeaderBytes + length];
            PeerEgressIpv6.WriteHeader(packet6, Ipv4ProtocolUdp, length, datagram.SourceIp6, datagram.DestinationIp6);
            var udp6 = packet6.AsSpan(PeerEgressIpv6.HeaderBytes);
            BinaryPrimitives.WriteUInt16BigEndian(udp6[0..2], datagram.SourcePort);
            BinaryPrimitives.WriteUInt16BigEndian(udp6[2..4], datagram.DestinationPort);
            BinaryPrimitives.WriteUInt16BigEndian(udp6[4..6], (ushort)length);
            datagram.Payload.CopyTo(udp6[UdpHeaderBytes..]);
            var checksum6 = PeerEgressIpv6.Checksum(datagram.SourceIp6, datagram.DestinationIp6, Ipv4ProtocolUdp, udp6);
            // Zero would read as "no checksum", which IPv6 does not allow; its complement is the same sum.
            BinaryPrimitives.WriteUInt16BigEndian(udp6[6..8], (ushort)(checksum6 == 0 ? 0xFFFF : checksum6));
            return packet6;
        }
        var packet = new byte[PeerEgressSegment.Ipv4MinHeaderBytes + length];

        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        packet[8] = 64;
        packet[9] = Ipv4ProtocolUdp;
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12, 4), datagram.SourceIp);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16, 4), datagram.DestinationIp);

        const int udp = PeerEgressSegment.Ipv4MinHeaderBytes;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(udp, 2), datagram.SourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(udp + 2, 2), datagram.DestinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(udp + 4, 2), (ushort)length);
        datagram.Payload.CopyTo(packet.AsSpan(udp + UdpHeaderBytes));

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10, 2), (ushort)Ipv4HeaderChecksum(packet));
        var checksum = UdpChecksum(packet, PeerEgressSegment.Ipv4MinHeaderBytes, length);
        // RFC 768: zero is reserved to mean "no checksum", so a computed zero goes on the wire as
        // its equivalent complement instead.
        if (checksum == 0)
        {
            checksum = 0xFFFF;
        }
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(udp + 6, 2), (ushort)checksum);
        return packet;
    }

    private static int Ipv4HeaderChecksum(ReadOnlySpan<byte> packet)
    {
        ulong sum = 0;
        for (var index = 0; index < PeerEgressSegment.Ipv4MinHeaderBytes; index += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(index, 2));
        }
        return Fold(sum);
    }

    /// <summary>
    /// The UDP checksum, pseudo-header included.
    /// </summary>
    /// <remarks>
    /// The TCP counterpart differs only in the protocol number, but the two cannot share code
    /// without making the segment layer's checksum take a parameter it never varies.
    /// </remarks>
    private static int UdpChecksum(ReadOnlySpan<byte> packet, int offset, int length)
    {
        ulong sum = 0;
        for (var index = 12; index < 20; index += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(index, 2));
        }
        sum += Ipv4ProtocolUdp;
        sum += (ulong)length;

        var cursor = offset;
        var end = offset + length;
        while (cursor + 1 < end)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(cursor, 2));
            cursor += 2;
        }
        if (cursor < end)
        {
            sum += (ulong)packet[cursor] << 8;
        }
        return Fold(sum);
    }

    private static int Fold(ulong sum)
    {
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int)(~sum & 0xFFFF);
    }
}
