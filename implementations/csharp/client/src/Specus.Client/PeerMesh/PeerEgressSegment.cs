using System.Buffers.Binary;

namespace Specus.Client.PeerMesh;

/// <summary>
/// TCP segment encoding and decoding for the egress user-space stack.
/// </summary>
/// <remarks>
/// The egress terminates TCP in user space rather than handing packets to the kernel, so acting as
/// an egress needs no NAT table, no routing table entry and no elevated privileges. That constraint
/// is what makes a Windows machine usable as an egress at all, and it is why this class exists
/// instead of a call into the operating system.
///
/// <para>Ported from the Go implementation and held to <c>peer-egress-tcp-v1.json</c>, the shared
/// fixture all three runtimes replay.</para>
/// </remarks>
internal static class PeerEgressSegment
{
    public const int FlagFin = 0x01;
    public const int FlagSyn = 0x02;
    public const int FlagRst = 0x04;
    public const int FlagPsh = 0x08;
    public const int FlagAck = 0x10;

    public const int TcpMinHeaderBytes = 20;
    public const int Ipv4MinHeaderBytes = 20;
    public const byte Ipv4ProtocolTcp = 6;

    /// <summary>What we advertise when the peer sends no MSS option: the IPv4 minimum everyone must accept.</summary>
    public const int DefaultMss = 536;

    /// <summary>One parsed TCP segment together with the IPv4 addresses that carried it.</summary>
    internal sealed record Segment(
        uint SourceIp,
        uint DestinationIp,
        ushort SourcePort,
        ushort DestinationPort,
        uint Seq,
        uint Ack,
        int Flags,
        int Window,
        int Mss,
        byte[] Payload)
    {
        public bool Has(int flag) => (Flags & flag) != 0;

        /// <summary>
        /// What the peer's sequence space advances by: payload plus one for each of SYN and FIN,
        /// which occupy a sequence number of their own.
        /// </summary>
        public uint SegmentLength()
        {
            var length = (uint)Payload.Length;
            if (Has(FlagSyn))
            {
                length++;
            }
            if (Has(FlagFin))
            {
                length++;
            }
            return length;
        }
    }

    /// <summary>
    /// Reads an IPv4 packet carrying TCP, or returns null for anything it cannot fully validate.
    /// A bad checksum returns null too: a segment we cannot trust must not advance any state.
    /// </summary>
    public static Segment? Parse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < Ipv4MinHeaderBytes)
        {
            return null;
        }
        if ((packet[0] >> 4) != 4 || packet[9] != Ipv4ProtocolTcp)
        {
            return null;
        }
        var ihl = (packet[0] & 0x0F) * 4;
        int total = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        if (ihl < Ipv4MinHeaderBytes || total < ihl + TcpMinHeaderBytes || total > packet.Length)
        {
            return null;
        }
        var dataOffset = (packet[ihl + 12] >> 4) * 4;
        if (dataOffset < TcpMinHeaderBytes || ihl + dataOffset > total)
        {
            return null;
        }
        if (TcpChecksum(packet[..total], ihl, total - ihl) != 0)
        {
            return null;
        }

        return new Segment(
            BinaryPrimitives.ReadUInt32BigEndian(packet[12..16]),
            BinaryPrimitives.ReadUInt32BigEndian(packet[16..20]),
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl, 2)),
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 2, 2)),
            BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(ihl + 4, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(ihl + 8, 4)),
            packet[ihl + 13],
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ihl + 14, 2)),
            ParseMss(packet.Slice(ihl + TcpMinHeaderBytes, dataOffset - TcpMinHeaderBytes)),
            packet[(ihl + dataOffset)..total].ToArray());
    }

    private static int ParseMss(ReadOnlySpan<byte> options)
    {
        var cursor = 0;
        while (cursor < options.Length)
        {
            int kind = options[cursor];
            if (kind == 0)
            {
                break;
            }
            if (kind == 1)
            {
                cursor++;
                continue;
            }
            if (cursor + 1 >= options.Length)
            {
                break;
            }
            int length = options[cursor + 1];
            if (length < 2 || cursor + length > options.Length)
            {
                break;
            }
            if (kind == 2 && length == 4)
            {
                return BinaryPrimitives.ReadUInt16BigEndian(options.Slice(cursor + 2, 2));
            }
            cursor += length;
        }
        return 0;
    }

    /// <summary>
    /// Renders a segment as a complete IPv4 packet, checksums included. An mss above zero emits the
    /// MSS option, which is only meaningful on a SYN.
    /// </summary>
    public static byte[] Build(Segment segment)
    {
        var optionBytes = segment.Mss > 0 ? 4 : 0;
        // The TCP header must end on a four-byte boundary; the option is already a multiple of
        // four, and the padding stays explicit so a future option cannot quietly break alignment.
        optionBytes = (optionBytes + 3) / 4 * 4;

        var tcpLength = TcpMinHeaderBytes + optionBytes + segment.Payload.Length;
        var packet = new byte[Ipv4MinHeaderBytes + tcpLength];

        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        packet[8] = 64;
        packet[9] = Ipv4ProtocolTcp;
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12, 4), segment.SourceIp);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16, 4), segment.DestinationIp);

        const int tcp = Ipv4MinHeaderBytes;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(tcp, 2), segment.SourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(tcp + 2, 2), segment.DestinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(tcp + 4, 4), segment.Seq);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(tcp + 8, 4), segment.Ack);
        packet[tcp + 12] = (byte)(((TcpMinHeaderBytes + optionBytes) / 4) << 4);
        packet[tcp + 13] = (byte)segment.Flags;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(tcp + 14, 2), (ushort)segment.Window);
        if (segment.Mss > 0)
        {
            packet[tcp + TcpMinHeaderBytes] = 2;
            packet[tcp + TcpMinHeaderBytes + 1] = 4;
            BinaryPrimitives.WriteUInt16BigEndian(
                packet.AsSpan(tcp + TcpMinHeaderBytes + 2, 2), (ushort)segment.Mss);
        }
        segment.Payload.CopyTo(packet.AsSpan(tcp + TcpMinHeaderBytes + optionBytes));

        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(10, 2), (ushort)Checksum(packet.AsSpan(0, Ipv4MinHeaderBytes)));
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(tcp + 16, 2), (ushort)TcpChecksum(packet, Ipv4MinHeaderBytes, tcpLength));
        return packet;
    }

    /// <summary>
    /// Answers an unwanted segment with a reset the peer's stack will accept.
    /// </summary>
    /// <remarks>
    /// RFC 793: a reset for a segment carrying ACK takes its sequence from that ACK; otherwise it
    /// acknowledges the incoming sequence space so the peer cannot dismiss it as out of window.
    /// Getting this wrong leaves the consumer retrying a refused flow until its own timeout.
    /// </remarks>
    public static byte[] BuildReset(Segment segment)
    {
        var flags = FlagRst;
        uint seq = 0;
        uint ack = 0;
        if (segment.Has(FlagAck))
        {
            seq = segment.Ack;
        }
        else
        {
            flags |= FlagAck;
            ack = segment.Seq + segment.SegmentLength();
        }
        return Build(new Segment(
            segment.DestinationIp, segment.SourceIp,
            segment.DestinationPort, segment.SourcePort,
            seq, ack, flags, 0, 0, []));
    }

    /// <summary>Reports a &lt; b in TCP's wrapping sequence space.</summary>
    public static bool SeqLess(uint a, uint b) => (int)(a - b) < 0;

    public static bool SeqLessEqual(uint a, uint b) => (int)(a - b) <= 0;

    /// <summary>
    /// Reports whether seq falls within [start, start+size). A zero window admits exactly the next
    /// expected byte, which is how a probe is recognised.
    /// </summary>
    public static bool SeqInWindow(uint seq, uint start, uint size)
    {
        if (size == 0)
        {
            return seq == start;
        }
        return !SeqLess(seq, start) && SeqLess(seq, start + size);
    }

    /// <summary>
    /// Renders the receive window into the sixteen bits the header has.
    /// </summary>
    /// <remarks>
    /// Clamped rather than truncated. A window of 65536 wraps to zero, and a zero window is not a
    /// large window: it is the signal that tells the peer to stop sending entirely and wait to be
    /// probed.
    /// </remarks>
    public static int AdvertisedWindow(uint window) => window > 0xFFFF ? 0xFFFF : (int)window;

    private static int Checksum(ReadOnlySpan<byte> data)
    {
        ulong sum = 0;
        var index = 0;
        while (index + 1 < data.Length)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(index, 2));
            index += 2;
        }
        if (index < data.Length)
        {
            sum += (ulong)data[index] << 8;
        }
        return Fold(sum);
    }

    /// <summary>
    /// The TCP checksum, pseudo-header included.
    /// </summary>
    /// <remarks>
    /// Written here rather than reusing the mesh packet helper: that one hard-codes the protocol
    /// number, and the egress needs the same shape again for UDP.
    /// </remarks>
    private static int TcpChecksum(ReadOnlySpan<byte> packet, int tcpOffset, int tcpLength)
    {
        ulong sum = 0;
        for (var index = 12; index < 20; index += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(index, 2));
        }
        sum += Ipv4ProtocolTcp;
        sum += (ulong)tcpLength;

        var cursor = tcpOffset;
        var end = tcpOffset + tcpLength;
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
