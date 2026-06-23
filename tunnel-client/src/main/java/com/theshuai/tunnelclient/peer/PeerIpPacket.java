package com.theshuai.tunnelclient.peer;

final class PeerIpPacket {
    private static final int IPV4_MIN_HEADER_BYTES = 20;
    private static final int IPV4_PROTOCOL_ICMP = 1;
    private static final int ICMP_ECHO_REPLY = 0;
    private static final int ICMP_ECHO_REQUEST = 8;

    private PeerIpPacket() {
    }

    static String destinationIpv4(byte[] packet) {
        if (packet == null || packet.length < IPV4_MIN_HEADER_BYTES) {
            return "";
        }
        int version = (packet[0] >>> 4) & 0x0F;
        int ihl = packet[0] & 0x0F;
        if (version != 4 || ihl < 5 || packet.length < ihl * 4) {
            return "";
        }
        return (packet[16] & 0xFF) + "."
                + (packet[17] & 0xFF) + "."
                + (packet[18] & 0xFF) + "."
                + (packet[19] & 0xFF);
    }

    static String sourceIpv4(byte[] packet) {
        if (packet == null || packet.length < IPV4_MIN_HEADER_BYTES) {
            return "";
        }
        int version = (packet[0] >>> 4) & 0x0F;
        int ihl = packet[0] & 0x0F;
        if (version != 4 || ihl < 5 || packet.length < ihl * 4) {
            return "";
        }
        return (packet[12] & 0xFF) + "."
                + (packet[13] & 0xFF) + "."
                + (packet[14] & 0xFF) + "."
                + (packet[15] & 0xFF);
    }

    static byte[] icmpEchoReplyFor(byte[] packet, String localVirtualIp) {
        if (!isIcmpEchoRequestFor(packet, localVirtualIp)) {
            return null;
        }
        int ihlBytes = (packet[0] & 0x0F) * 4;
        int totalLength = totalLength(packet);
        byte[] reply = new byte[totalLength];
        System.arraycopy(packet, 0, reply, 0, totalLength);

        for (int i = 0; i < 4; i++) {
            byte source = reply[12 + i];
            reply[12 + i] = reply[16 + i];
            reply[16 + i] = source;
        }
        reply[8] = 64;
        reply[10] = 0;
        reply[11] = 0;

        int icmpOffset = ihlBytes;
        reply[icmpOffset] = ICMP_ECHO_REPLY;
        reply[icmpOffset + 1] = 0;
        reply[icmpOffset + 2] = 0;
        reply[icmpOffset + 3] = 0;
        int icmpChecksum = checksum(reply, icmpOffset, totalLength - icmpOffset);
        reply[icmpOffset + 2] = (byte) ((icmpChecksum >>> 8) & 0xFF);
        reply[icmpOffset + 3] = (byte) (icmpChecksum & 0xFF);

        int ipChecksum = checksum(reply, 0, ihlBytes);
        reply[10] = (byte) ((ipChecksum >>> 8) & 0xFF);
        reply[11] = (byte) (ipChecksum & 0xFF);
        return reply;
    }

    private static boolean isIcmpEchoRequestFor(byte[] packet, String localVirtualIp) {
        if (packet == null || packet.length < IPV4_MIN_HEADER_BYTES || !destinationIpv4(packet).equals(localVirtualIp)) {
            return false;
        }
        int ihlBytes = (packet[0] & 0x0F) * 4;
        int totalLength = totalLength(packet);
        return totalLength >= ihlBytes + 8
                && totalLength <= packet.length
                && (packet[9] & 0xFF) == IPV4_PROTOCOL_ICMP
                && (packet[ihlBytes] & 0xFF) == ICMP_ECHO_REQUEST
                && (packet[ihlBytes + 1] & 0xFF) == 0;
    }

    private static int totalLength(byte[] packet) {
        if (packet == null || packet.length < 4) {
            return 0;
        }
        int totalLength = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
        return totalLength > 0 && totalLength <= packet.length ? totalLength : packet.length;
    }

    private static int checksum(byte[] packet, int offset, int length) {
        long sum = 0;
        int index = offset;
        int end = offset + length;
        while (index + 1 < end) {
            sum += ((packet[index] & 0xFF) << 8) | (packet[index + 1] & 0xFF);
            index += 2;
        }
        if (index < end) {
            sum += (packet[index] & 0xFF) << 8;
        }
        while ((sum >>> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
        return (int) (~sum) & 0xFFFF;
    }
}
