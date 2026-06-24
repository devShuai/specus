package com.theshuai.tunnelclient.peer;

final class PeerIpPacket {
    private static final int IPV4_MIN_HEADER_BYTES = 20;
    private static final int IPV4_PROTOCOL_ICMP = 1;
    private static final int IPV4_PROTOCOL_TCP = 6;
    private static final int IPV4_PROTOCOL_UDP = 17;
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

    static int protocol(byte[] packet) {
        if (packet == null || packet.length < IPV4_MIN_HEADER_BYTES) {
            return -1;
        }
        int version = (packet[0] >>> 4) & 0x0F;
        int ihl = packet[0] & 0x0F;
        if (version != 4 || ihl < 5 || packet.length < ihl * 4) {
            return -1;
        }
        return packet[9] & 0xFF;
    }

    static String describe(byte[] packet) {
        int protocol = protocol(packet);
        String protocolName = switch (protocol) {
            case IPV4_PROTOCOL_ICMP -> "ICMP";
            case IPV4_PROTOCOL_TCP -> "TCP";
            case IPV4_PROTOCOL_UDP -> "UDP";
            default -> protocol < 0 ? "IPv4?" : "IP-" + protocol;
        };
        String source = sourceIpv4(packet);
        String target = destinationIpv4(packet);
        int sourcePort = sourcePort(packet);
        int targetPort = destinationPort(packet);
        if ((protocol == IPV4_PROTOCOL_TCP || protocol == IPV4_PROTOCOL_UDP) && sourcePort > 0 && targetPort > 0) {
            return protocolName + " " + source + ":" + sourcePort + " -> " + target + ":" + targetPort;
        }
        return protocolName + " " + source + " -> " + target;
    }

    static String flowKey(byte[] packet) {
        return protocol(packet) + "|" + sourceIpv4(packet) + "|" + sourcePort(packet)
                + "|" + destinationIpv4(packet) + "|" + destinationPort(packet);
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

    private static int sourcePort(byte[] packet) {
        int offset = transportOffset(packet);
        if (offset < 0 || packet.length < offset + 4) {
            return -1;
        }
        int protocol = protocol(packet);
        if (protocol != IPV4_PROTOCOL_TCP && protocol != IPV4_PROTOCOL_UDP) {
            return -1;
        }
        return ((packet[offset] & 0xFF) << 8) | (packet[offset + 1] & 0xFF);
    }

    private static int destinationPort(byte[] packet) {
        int offset = transportOffset(packet);
        if (offset < 0 || packet.length < offset + 4) {
            return -1;
        }
        int protocol = protocol(packet);
        if (protocol != IPV4_PROTOCOL_TCP && protocol != IPV4_PROTOCOL_UDP) {
            return -1;
        }
        return ((packet[offset + 2] & 0xFF) << 8) | (packet[offset + 3] & 0xFF);
    }

    private static int transportOffset(byte[] packet) {
        if (packet == null || packet.length < IPV4_MIN_HEADER_BYTES) {
            return -1;
        }
        int version = (packet[0] >>> 4) & 0x0F;
        int ihl = packet[0] & 0x0F;
        int offset = ihl * 4;
        if (version != 4 || ihl < 5 || packet.length < offset) {
            return -1;
        }
        return offset;
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
