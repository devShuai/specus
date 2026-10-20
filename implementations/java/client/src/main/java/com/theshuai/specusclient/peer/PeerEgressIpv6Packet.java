package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.Ipv6Cidr;
import java.util.Arrays;

/**
 * The egress side of the IPv6 data plane ({@code protocol/spec/peer-egress.md}, IPv6 数据面): the
 * address a device has in it, and the IPv6 packets the user-space stack reads from consumers and
 * writes back.
 *
 * <p>The stack is the IPv4 one. A segment or datagram carries the family it arrived in, and
 * everything above the codec -- the state machine, the flow table, the judgment layer -- works on it
 * unchanged.
 */
final class PeerEgressIpv6Packet {

    /**
     * This egress accepts IPv6 packets in SPEG1 type=1 frames, and so announces
     * {@code ipv6PacketCapable} at login. The consumer side is separate:
     * {@link com.theshuai.common.peeregress.PeerEgressRules#CONSUMER_CARRIES_IPV6} says whether this
     * device sends IPv6 to an egress, and stays false until the consumer data plane exists.
     */
    static final boolean PACKET_CAPABLE = true;

    static final int HEADER_BYTES = 40;

    /**
     * ICMPv6. Like every next header but TCP and UDP it is refused, and named only so the tests can
     * say what they send.
     */
    static final int NEXT_HEADER_ICMP = 58;

    /** What the egress writes on every packet it returns to a consumer. */
    static final int HOP_LIMIT = 64;

    /**
     * The largest payload an IPv6 datagram without a jumbogram can carry: the payload length field
     * counts the UDP header but not the fixed IPv6 header.
     */
    static final int UDP_MAX_PAYLOAD = 65535 - PeerEgressDatagram.UDP_HEADER_BYTES;

    /** The derived prefix's first 64 bits; the next 32 are zero and the last 32 are the mesh IPv4. */
    private static final long MESH_PREFIX_HIGH = 0xfd53_7065_6375_7300L;

    private PeerEgressIpv6Packet() {
    }

    /**
     * An IPv6 address as two halves, which is how {@link Ipv6Cidr} holds one. A value type so that
     * the flow key built from it compares by content.
     */
    record Address(long high, long low) implements Comparable<Address> {

        static final Address ZERO = new Address(0, 0);

        /** Reads the pinned spelling ({@link Ipv6Cidr#parseAddress}), or null. */
        static Address parse(String text) {
            long[] halves = Ipv6Cidr.parseAddress(text);
            return halves == null ? null : new Address(halves[0], halves[1]);
        }

        /** Sixteen bytes of a packet, in network order. */
        static Address read(byte[] packet, int offset) {
            long high = 0;
            long low = 0;
            for (int index = 0; index < 8; index++) {
                high = (high << 8) | (packet[offset + index] & 0xFFL);
                low = (low << 8) | (packet[offset + 8 + index] & 0xFFL);
            }
            return new Address(high, low);
        }

        void write(byte[] packet, int offset) {
            for (int index = 0; index < 8; index++) {
                packet[offset + index] = (byte) (high >>> (56 - 8 * index));
                packet[offset + 8 + index] = (byte) (low >>> (56 - 8 * index));
            }
        }

        long[] halves() {
            return new long[] {high, low};
        }

        /** RFC 5952 form, the way flow-reject and the judgment write it. */
        String format() {
            return Ipv6Cidr.formatAddress(high, low);
        }

        /** Addresses are unsigned: compared half by half as unsigned numbers. */
        @Override
        public int compareTo(Address other) {
            int byHigh = Long.compareUnsigned(high, other.high);
            return byHigh != 0 ? byHigh : Long.compareUnsigned(low, other.low);
        }

        @Override
        public String toString() {
            return format();
        }
    }

    /** The IPv6 address derived from a mesh IPv4 address: the prefix with the IPv4 as its low 32 bits. */
    static Address meshAddress(int meshIpv4) {
        return new Address(MESH_PREFIX_HIGH, meshIpv4 & 0xFFFFFFFFL);
    }

    /**
     * Reads the mesh IPv4 address back out of a derived address, or null: only an address inside
     * the prefix is one.
     */
    static Integer meshIpv4(Address address) {
        if (address.high() != MESH_PREFIX_HIGH || (address.low() >>> 32) != 0) {
            return null;
        }
        return (int) address.low();
    }

    /**
     * Derives a device's IPv6 address from its mesh IPv4 as the mesh writes it, or null when that is
     * not an IPv4 address at all -- a session whose peer has no known mesh address.
     */
    static Address deviceAddress(String meshIpv4) {
        Integer address = Ipv4Cidr.parseAddress(meshIpv4);
        return address == null ? null : meshAddress(address);
    }

    /**
     * Reads an IPv6 packet whose next header is TCP, or returns null for anything it cannot fully
     * validate, a bad checksum included. A TCP header behind an extension header is not read: the
     * frame layer has already sent anything but a bare TCP or UDP payload to the protocol refusal.
     */
    static PeerEgressSegment.Segment parseSegment(byte[] packet) {
        if (!carries(packet, PeerEgressSegment.IPV4_PROTOCOL_TCP)) {
            return null;
        }
        int length = packet.length - HEADER_BYTES;
        if (length < PeerEgressSegment.TCP_MIN_HEADER_BYTES) {
            return null;
        }
        int tcp = HEADER_BYTES;
        int dataOffset = ((packet[tcp + 12] >>> 4) & 0x0F) * 4;
        if (dataOffset < PeerEgressSegment.TCP_MIN_HEADER_BYTES || dataOffset > length) {
            return null;
        }
        Address source = Address.read(packet, 8);
        Address destination = Address.read(packet, 24);
        if (checksum(source, destination, PeerEgressSegment.IPV4_PROTOCOL_TCP, packet, tcp, length) != 0) {
            return null;
        }
        return new PeerEgressSegment.Segment(
                0, 0,
                PeerEgressSegment.readShort(packet, tcp),
                PeerEgressSegment.readShort(packet, tcp + 2),
                PeerEgressSegment.readInt(packet, tcp + 4),
                PeerEgressSegment.readInt(packet, tcp + 8),
                packet[tcp + 13] & 0xFF,
                PeerEgressSegment.readShort(packet, tcp + 14),
                PeerEgressSegment.parseMss(packet, tcp + PeerEgressSegment.TCP_MIN_HEADER_BYTES, tcp + dataOffset),
                Arrays.copyOfRange(packet, tcp + dataOffset, packet.length),
                source, destination);
    }

    /**
     * Reads an IPv6 packet whose next header is UDP, or returns null.
     *
     * <p>A zero checksum is refused rather than read as "none": IPv4 lets a sender leave it out,
     * IPv6 does not (RFC 8200 8.1), because there is no header checksum underneath to catch a
     * damaged address.
     */
    static PeerEgressDatagram.Datagram parseDatagram(byte[] packet) {
        if (!carries(packet, PeerEgressDatagram.IPV4_PROTOCOL_UDP)) {
            return null;
        }
        int length = packet.length - HEADER_BYTES;
        int udp = HEADER_BYTES;
        if (length < PeerEgressDatagram.UDP_HEADER_BYTES || PeerEgressSegment.readShort(packet, udp + 4) != length) {
            return null;
        }
        Address source = Address.read(packet, 8);
        Address destination = Address.read(packet, 24);
        if (PeerEgressSegment.readShort(packet, udp + 6) == 0
                || checksum(source, destination, PeerEgressDatagram.IPV4_PROTOCOL_UDP, packet, udp, length) != 0) {
            return null;
        }
        return new PeerEgressDatagram.Datagram(
                0, 0,
                PeerEgressSegment.readShort(packet, udp),
                PeerEgressSegment.readShort(packet, udp + 2),
                Arrays.copyOfRange(packet, udp + PeerEgressDatagram.UDP_HEADER_BYTES, packet.length),
                source, destination);
    }

    /**
     * Whether packet is IPv6 carrying nextHeader directly after the fixed header, with exactly the
     * length the header states.
     */
    private static boolean carries(byte[] packet, int nextHeader) {
        if (packet == null || packet.length < HEADER_BYTES || ((packet[0] >>> 4) & 0x0F) != 6
                || (packet[6] & 0xFF) != nextHeader) {
            return false;
        }
        return HEADER_BYTES + PeerEgressSegment.readShort(packet, 4) == packet.length;
    }

    /**
     * Fills the fixed header of a packet the egress returns: traffic class and flow label zero, hop
     * limit 64.
     */
    static void writeHeader(byte[] packet, int nextHeader, int payloadLength, Address source, Address destination) {
        packet[0] = 0x60;
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
        PeerEgressSegment.writeShort(packet, 4, payloadLength);
        packet[6] = (byte) nextHeader;
        packet[7] = (byte) HOP_LIMIT;
        source.write(packet, 8);
        destination.write(packet, 24);
    }

    /**
     * The TCP and UDP checksum over the RFC 8200 8.1 pseudo-header: both addresses, the
     * upper-layer length as 32 bits, three zero bytes and the next header. Over a segment that
     * already carries its checksum it comes to zero, the same convention as the IPv4 helpers.
     */
    static int checksum(Address source, Address destination, int nextHeader, byte[] data, int offset, int length) {
        long sum = 0;
        for (Address address : new Address[] {source, destination}) {
            for (long half : address.halves()) {
                for (int shift = 48; shift >= 0; shift -= 16) {
                    sum += (half >>> shift) & 0xFFFF;
                }
            }
        }
        sum += (length >>> 16) & 0xFFFF;
        sum += length & 0xFFFF;
        sum += nextHeader;
        int index = offset;
        int end = offset + length;
        while (index + 1 < end) {
            sum += PeerEgressSegment.readShort(data, index);
            index += 2;
        }
        if (index < end) {
            sum += (long) (data[index] & 0xFF) << 8;
        }
        while ((sum >>> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
        return (int) (~sum & 0xFFFF);
    }
}
