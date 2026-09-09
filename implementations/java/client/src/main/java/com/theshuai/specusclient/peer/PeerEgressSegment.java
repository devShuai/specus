package com.theshuai.specusclient.peer;

import java.util.Arrays;

/**
 * TCP segment encoding and decoding for the egress user-space stack.
 *
 * <p>The egress terminates TCP in user space rather than handing packets to the kernel, so that
 * acting as an egress needs no NAT table, no routing table entry and no elevated privileges. That
 * constraint is what makes a Windows machine usable as an egress at all, and it is why this class
 * exists instead of a call into the operating system.
 *
 * <p>Ported from the Go implementation and held to {@code peer-egress-tcp-v1.json}, the shared
 * fixture all three runtimes replay.
 */
final class PeerEgressSegment {

    static final int FLAG_FIN = 0x01;
    static final int FLAG_SYN = 0x02;
    static final int FLAG_RST = 0x04;
    static final int FLAG_PSH = 0x08;
    static final int FLAG_ACK = 0x10;

    static final int TCP_MIN_HEADER_BYTES = 20;
    static final int IPV4_MIN_HEADER_BYTES = 20;
    static final int IPV4_PROTOCOL_TCP = 6;

    /** What we advertise when the peer sends no MSS option: the IPv4 minimum everyone must accept. */
    static final int DEFAULT_MSS = 536;

    private static final byte[] EMPTY = new byte[0];

    private PeerEgressSegment() {
    }

    /** One parsed TCP segment together with the IPv4 addresses that carried it. */
    record Segment(
            int sourceIp,
            int destinationIp,
            int sourcePort,
            int destinationPort,
            int seq,
            int ack,
            int flags,
            int window,
            int mss,
            byte[] payload) {

        Segment {
            payload = payload == null ? EMPTY : payload;
        }

        boolean has(int flag) {
            return (flags & flag) != 0;
        }

        /**
         * What the peer's sequence space advances by: payload plus one for each of SYN and FIN,
         * which occupy a sequence number of their own.
         */
        int segmentLength() {
            int length = payload.length;
            if (has(FLAG_SYN)) {
                length++;
            }
            if (has(FLAG_FIN)) {
                length++;
            }
            return length;
        }
    }

    /**
     * Reads an IPv4 packet carrying TCP, or returns null for anything it cannot fully validate.
     *
     * <p>A bad checksum returns null too: a segment we cannot trust must not advance any state.
     */
    static Segment parse(byte[] packet) {
        if (packet == null || packet.length < IPV4_MIN_HEADER_BYTES) {
            return null;
        }
        if (((packet[0] >>> 4) & 0x0F) != 4 || (packet[9] & 0xFF) != IPV4_PROTOCOL_TCP) {
            return null;
        }
        int ihl = (packet[0] & 0x0F) * 4;
        int total = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
        if (ihl < IPV4_MIN_HEADER_BYTES
                || total < ihl + TCP_MIN_HEADER_BYTES
                || total > packet.length) {
            return null;
        }
        int dataOffset = ((packet[ihl + 12] >>> 4) & 0x0F) * 4;
        if (dataOffset < TCP_MIN_HEADER_BYTES || ihl + dataOffset > total) {
            return null;
        }
        if (tcpChecksum(packet, ihl, total - ihl) != 0) {
            return null;
        }
        byte[] payload = Arrays.copyOfRange(packet, ihl + dataOffset, total);
        return new Segment(
                readInt(packet, 12),
                readInt(packet, 16),
                readShort(packet, ihl),
                readShort(packet, ihl + 2),
                readInt(packet, ihl + 4),
                readInt(packet, ihl + 8),
                packet[ihl + 13] & 0xFF,
                readShort(packet, ihl + 14),
                parseMss(packet, ihl + TCP_MIN_HEADER_BYTES, ihl + dataOffset),
                payload);
    }

    private static int parseMss(byte[] packet, int from, int to) {
        int cursor = from;
        while (cursor < to) {
            int kind = packet[cursor] & 0xFF;
            if (kind == 0) {
                break;
            }
            if (kind == 1) {
                cursor++;
                continue;
            }
            if (cursor + 1 >= to) {
                break;
            }
            int length = packet[cursor + 1] & 0xFF;
            if (length < 2 || cursor + length > to) {
                break;
            }
            if (kind == 2 && length == 4) {
                return readShort(packet, cursor + 2);
            }
            cursor += length;
        }
        return 0;
    }

    /**
     * Renders a segment as a complete IPv4 packet, checksums included.
     *
     * <p>An mss above zero emits the MSS option, which is only meaningful on a SYN.
     */
    static byte[] build(Segment segment) {
        byte[] options = EMPTY;
        if (segment.mss() > 0) {
            options = new byte[] {2, 4, (byte) (segment.mss() >>> 8), (byte) segment.mss()};
        }
        // The TCP header must end on a four-byte boundary; pad with NOP/EOL.
        int padded = ((options.length + 3) / 4) * 4;
        if (padded != options.length) {
            options = Arrays.copyOf(options, padded);
        }

        int tcpLength = TCP_MIN_HEADER_BYTES + options.length + segment.payload().length;
        byte[] packet = new byte[IPV4_MIN_HEADER_BYTES + tcpLength];

        packet[0] = 0x45;
        writeShort(packet, 2, packet.length);
        packet[8] = 64;
        packet[9] = (byte) IPV4_PROTOCOL_TCP;
        writeInt(packet, 12, segment.sourceIp());
        writeInt(packet, 16, segment.destinationIp());

        int tcp = IPV4_MIN_HEADER_BYTES;
        writeShort(packet, tcp, segment.sourcePort());
        writeShort(packet, tcp + 2, segment.destinationPort());
        writeInt(packet, tcp + 4, segment.seq());
        writeInt(packet, tcp + 8, segment.ack());
        packet[tcp + 12] = (byte) (((TCP_MIN_HEADER_BYTES + options.length) / 4) << 4);
        packet[tcp + 13] = (byte) segment.flags();
        writeShort(packet, tcp + 14, segment.window());
        System.arraycopy(options, 0, packet, tcp + TCP_MIN_HEADER_BYTES, options.length);
        System.arraycopy(
                segment.payload(), 0,
                packet, tcp + TCP_MIN_HEADER_BYTES + options.length, segment.payload().length);

        writeShort(packet, 10, checksum(packet, 0, IPV4_MIN_HEADER_BYTES));
        writeShort(packet, tcp + 16, tcpChecksum(packet, IPV4_MIN_HEADER_BYTES, tcpLength));
        return packet;
    }

    /**
     * Answers an unwanted segment with a reset the peer's stack will accept.
     *
     * <p>RFC 793: a reset for a segment carrying ACK takes its sequence from that ACK; otherwise it
     * acknowledges the incoming sequence space so the peer cannot dismiss it as out of window.
     * Getting this wrong leaves the consumer retrying a refused flow until its own timeout.
     */
    static byte[] buildReset(Segment segment) {
        int flags = FLAG_RST;
        int seq = 0;
        int ack = 0;
        if (segment.has(FLAG_ACK)) {
            seq = segment.ack();
        } else {
            flags |= FLAG_ACK;
            ack = segment.seq() + segment.segmentLength();
        }
        return build(new Segment(
                segment.destinationIp(), segment.sourceIp(),
                segment.destinationPort(), segment.sourcePort(),
                seq, ack, flags, 0, 0, EMPTY));
    }

    /** Reports a &lt; b in TCP's wrapping sequence space. */
    static boolean seqLess(int a, int b) {
        return a - b < 0;
    }

    static boolean seqLessEqual(int a, int b) {
        return a - b <= 0;
    }

    /**
     * Reports whether seq falls within [start, start+size).
     *
     * <p>A zero window admits exactly the next expected byte, which is how a probe is recognised.
     */
    static boolean seqInWindow(int seq, int start, int size) {
        if (size == 0) {
            return seq == start;
        }
        return !seqLess(seq, start) && seqLess(seq, start + size);
    }

    /**
     * Renders the receive window into the sixteen bits the header has.
     *
     * <p>Clamped rather than truncated. A window of 65536 wraps to zero, and a zero window is not a
     * large window: it is the signal that tells the peer to stop sending entirely and wait to be
     * probed.
     */
    static int advertisedWindow(int window) {
        return window > 0xFFFF ? 0xFFFF : window;
    }

    static int readShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    static int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    static void writeShort(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >>> 8) & 0xFF);
        data[offset + 1] = (byte) (value & 0xFF);
    }

    static void writeInt(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >>> 24) & 0xFF);
        data[offset + 1] = (byte) ((value >>> 16) & 0xFF);
        data[offset + 2] = (byte) ((value >>> 8) & 0xFF);
        data[offset + 3] = (byte) (value & 0xFF);
    }

    private static int checksum(byte[] data, int offset, int length) {
        long sum = 0;
        int index = offset;
        int end = offset + length;
        while (index + 1 < end) {
            sum += readShort(data, index);
            index += 2;
        }
        if (index < end) {
            sum += (long) (data[index] & 0xFF) << 8;
        }
        return fold(sum);
    }

    /**
     * The TCP checksum, pseudo-header included.
     *
     * <p>Written here rather than reusing the mesh packet helper: that one is private to its own
     * class and hard-codes the protocol number, and the egress needs the same shape again for UDP.
     */
    private static int tcpChecksum(byte[] packet, int tcpOffset, int tcpLength) {
        long sum = 0;
        for (int index = 12; index < 20; index += 2) {
            sum += readShort(packet, index);
        }
        sum += IPV4_PROTOCOL_TCP;
        sum += tcpLength;
        int index = tcpOffset;
        int end = tcpOffset + tcpLength;
        while (index + 1 < end) {
            sum += readShort(packet, index);
            index += 2;
        }
        if (index < end) {
            sum += (long) (packet[index] & 0xFF) << 8;
        }
        return fold(sum);
    }

    private static int fold(long sum) {
        while ((sum >>> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
        return (int) (~sum & 0xFFFF);
    }
}
