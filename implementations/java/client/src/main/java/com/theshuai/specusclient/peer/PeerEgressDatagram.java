package com.theshuai.specusclient.peer;

import java.util.Arrays;

/**
 * UDP datagram encoding and decoding for the egress user-space stack.
 *
 * <p>The counterpart of {@link PeerEgressSegment}. The egress terminates UDP in user space for the
 * same reason it terminates TCP there: no NAT table, no routing entry and no elevated privileges,
 * which is what lets an ordinary desktop act as an egress.
 *
 * <p>QUIC needs nothing of its own. It rides on UDP, so it is carried by exactly this path as one
 * long-lived session per four-tuple, kept alive by its own traffic rather than by anything here.
 */
final class PeerEgressDatagram {

    static final int UDP_HEADER_BYTES = 8;
    static final int IPV4_PROTOCOL_UDP = 17;

    /**
     * The largest payload an IPv4 datagram can carry: 65535 less the minimum IPv4 header and the
     * UDP header. Anything claiming more is malformed, not merely large.
     */
    static final int MAX_PAYLOAD = 65535 - PeerEgressSegment.IPV4_MIN_HEADER_BYTES - UDP_HEADER_BYTES;

    private static final byte[] EMPTY = new byte[0];

    private PeerEgressDatagram() {
    }

    /** One parsed UDP datagram together with the IPv4 addresses that carried it. */
    record Datagram(
            int sourceIp,
            int destinationIp,
            int sourcePort,
            int destinationPort,
            byte[] payload) {

        Datagram {
            payload = payload == null ? EMPTY : payload;
        }
    }

    /**
     * Reads an IPv4 packet carrying UDP, or returns null for anything it cannot fully validate.
     *
     * <p>Like the TCP parser it refuses rather than returning a best-effort result: a datagram we
     * cannot trust must not open a session or reach a real socket.
     */
    static Datagram parse(byte[] packet) {
        if (packet == null || packet.length < PeerEgressSegment.IPV4_MIN_HEADER_BYTES) {
            return null;
        }
        if (((packet[0] >>> 4) & 0x0F) != 4 || (packet[9] & 0xFF) != IPV4_PROTOCOL_UDP) {
            return null;
        }
        int ihl = (packet[0] & 0x0F) * 4;
        int total = PeerEgressSegment.readShort(packet, 2);
        if (ihl < PeerEgressSegment.IPV4_MIN_HEADER_BYTES
                || total < ihl + UDP_HEADER_BYTES
                || total > packet.length) {
            return null;
        }
        int length = PeerEgressSegment.readShort(packet, ihl + 4);
        // The UDP length must describe exactly the bytes IPv4 delivered. Accepting a shorter one
        // would let a sender smuggle trailing bytes past us, which is why the frame layer refuses
        // trailing bytes too.
        if (length != total - ihl || length > UDP_HEADER_BYTES + MAX_PAYLOAD) {
            return null;
        }
        // A zero checksum means the sender did not compute one, which IPv4 permits. Present means
        // it must be right.
        if (PeerEgressSegment.readShort(packet, ihl + 6) != 0
                && udpChecksum(packet, ihl, length) != 0) {
            return null;
        }
        return new Datagram(
                PeerEgressSegment.readInt(packet, 12),
                PeerEgressSegment.readInt(packet, 16),
                PeerEgressSegment.readShort(packet, ihl),
                PeerEgressSegment.readShort(packet, ihl + 2),
                Arrays.copyOfRange(packet, ihl + UDP_HEADER_BYTES, total));
    }

    /** Renders a datagram as a complete IPv4 packet, checksums included. */
    static byte[] build(Datagram datagram) {
        int length = UDP_HEADER_BYTES + datagram.payload().length;
        byte[] packet = new byte[PeerEgressSegment.IPV4_MIN_HEADER_BYTES + length];

        packet[0] = 0x45;
        PeerEgressSegment.writeShort(packet, 2, packet.length);
        packet[8] = 64;
        packet[9] = (byte) IPV4_PROTOCOL_UDP;
        PeerEgressSegment.writeInt(packet, 12, datagram.sourceIp());
        PeerEgressSegment.writeInt(packet, 16, datagram.destinationIp());

        int udp = PeerEgressSegment.IPV4_MIN_HEADER_BYTES;
        PeerEgressSegment.writeShort(packet, udp, datagram.sourcePort());
        PeerEgressSegment.writeShort(packet, udp + 2, datagram.destinationPort());
        PeerEgressSegment.writeShort(packet, udp + 4, length);
        System.arraycopy(
                datagram.payload(), 0,
                packet, udp + UDP_HEADER_BYTES, datagram.payload().length);

        PeerEgressSegment.writeShort(
                packet, 10, ipv4HeaderChecksum(packet));
        int checksum = udpChecksum(packet, PeerEgressSegment.IPV4_MIN_HEADER_BYTES, length);
        // RFC 768: zero is reserved to mean "no checksum", so a computed zero goes on the wire as
        // its equivalent complement instead.
        if (checksum == 0) {
            checksum = 0xFFFF;
        }
        PeerEgressSegment.writeShort(packet, udp + 6, checksum);
        return packet;
    }

    private static int ipv4HeaderChecksum(byte[] packet) {
        long sum = 0;
        for (int index = 0; index < PeerEgressSegment.IPV4_MIN_HEADER_BYTES; index += 2) {
            sum += PeerEgressSegment.readShort(packet, index);
        }
        return fold(sum);
    }

    /**
     * The UDP checksum, pseudo-header included.
     *
     * <p>The TCP counterpart differs only in the protocol number, but the two cannot share code
     * without making the segment layer's checksum take a parameter it never varies.
     */
    private static int udpChecksum(byte[] packet, int offset, int length) {
        long sum = 0;
        for (int index = 12; index < 20; index += 2) {
            sum += PeerEgressSegment.readShort(packet, index);
        }
        sum += IPV4_PROTOCOL_UDP;
        sum += length;

        int index = offset;
        int end = offset + length;
        while (index + 1 < end) {
            sum += PeerEgressSegment.readShort(packet, index);
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
