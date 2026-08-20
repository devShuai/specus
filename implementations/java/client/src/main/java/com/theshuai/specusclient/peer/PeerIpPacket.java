package com.theshuai.specusclient.peer;

import java.util.Arrays;

final class PeerIpPacket {
    private static final int IPV4_MIN_HEADER_BYTES = 20;
    private static final int IPV4_PROTOCOL_ICMP = 1;
    private static final int IPV4_PROTOCOL_TCP = 6;
    private static final int IPV4_PROTOCOL_UDP = 17;
    private static final int ICMP_ECHO_REPLY = 0;
    private static final int ICMP_ECHO_REQUEST = 8;
    private static final int ICMP_DESTINATION_UNREACHABLE = 3;
    private static final int ICMP_FRAGMENTATION_NEEDED = 4;

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

    static Integer destinationIpv4Int(byte[] packet) {
        return packet == null ? null : destinationIpv4Int(packet, 0, packet.length);
    }

    static Integer destinationIpv4Int(byte[] packet, int offset, int length) {
        if (packet == null
                || offset < 0
                || length < IPV4_MIN_HEADER_BYTES
                || offset > packet.length - length) {
            return null;
        }
        int version = (packet[offset] >>> 4) & 0x0F;
        int ihl = packet[offset] & 0x0F;
        if (version != 4 || ihl < 5 || length < ihl * 4) {
            return null;
        }
        return ((packet[offset + 16] & 0xFF) << 24)
                | ((packet[offset + 17] & 0xFF) << 16)
                | ((packet[offset + 18] & 0xFF) << 8)
                | (packet[offset + 19] & 0xFF);
    }

    static String ipv4ToString(int value) {
        return ((value >>> 24) & 0xFF) + "."
                + ((value >>> 16) & 0xFF) + "."
                + ((value >>> 8) & 0xFF) + "."
                + (value & 0xFF);
    }

    static Integer ipv4ToInt(String value) {
        if (value == null) {
            return null;
        }
        String[] parts = value.trim().split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        int result = 0;
        try {
            for (String part : parts) {
                if (part.isEmpty() || (part.length() > 1 && part.charAt(0) == '0')) {
                    return null;
                }
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return null;
                }
                result = (result << 8) | octet;
            }
            return result;
        } catch (NumberFormatException ignored) {
            return null;
        }
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

    static boolean matchesAuthenticatedEndpoints(byte[] packet, String peerVirtualIp, String localVirtualIp) {
        return peerVirtualIp != null
                && localVirtualIp != null
                && peerVirtualIp.equals(sourceIpv4(packet))
                && localVirtualIp.equals(destinationIpv4(packet));
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

    static byte[] clampTcpMss(byte[] packet, int pathMtu) {
        if (!hasValidIpv4Header(packet) || protocol(packet) != IPV4_PROTOCOL_TCP) {
            return packet;
        }
        int ipHeaderBytes = (packet[0] & 0x0F) * 4;
        int totalLength = totalLength(packet);
        if (totalLength < ipHeaderBytes + 20 || (packet[ipHeaderBytes + 13] & 0x02) == 0) {
            return packet;
        }
        int tcpHeaderBytes = ((packet[ipHeaderBytes + 12] >>> 4) & 0x0F) * 4;
        if (tcpHeaderBytes < 20 || totalLength < ipHeaderBytes + tcpHeaderBytes) {
            return packet;
        }
        int maxMss = Math.max(536, pathMtu - ipHeaderBytes - 20);
        int cursor = ipHeaderBytes + 20;
        int end = ipHeaderBytes + tcpHeaderBytes;
        while (cursor < end) {
            int kind = packet[cursor] & 0xFF;
            if (kind == 0) {
                break;
            }
            if (kind == 1) {
                cursor++;
                continue;
            }
            if (cursor + 1 >= end) {
                break;
            }
            int optionLength = packet[cursor + 1] & 0xFF;
            if (optionLength < 2 || cursor + optionLength > end) {
                break;
            }
            if (kind == 2 && optionLength == 4) {
                int advertised = ((packet[cursor + 2] & 0xFF) << 8) | (packet[cursor + 3] & 0xFF);
                if (advertised <= maxMss) {
                    return packet;
                }
                byte[] clamped = Arrays.copyOf(packet, packet.length);
                clamped[cursor + 2] = (byte) (maxMss >>> 8);
                clamped[cursor + 3] = (byte) maxMss;
                clamped[ipHeaderBytes + 16] = 0;
                clamped[ipHeaderBytes + 17] = 0;
                int tcpChecksum = tcpChecksum(clamped, ipHeaderBytes, totalLength - ipHeaderBytes);
                clamped[ipHeaderBytes + 16] = (byte) (tcpChecksum >>> 8);
                clamped[ipHeaderBytes + 17] = (byte) tcpChecksum;
                return clamped;
            }
            cursor += optionLength;
        }
        return packet;
    }

    static byte[] icmpFragmentationNeededFor(byte[] packet, int pathMtu) {
        if (!hasValidIpv4Header(packet)) {
            return null;
        }
        int originalHeaderBytes = (packet[0] & 0x0F) * 4;
        int originalLength = totalLength(packet);
        int quotedLength = Math.min(originalLength, originalHeaderBytes + 8);
        byte[] response = new byte[20 + 8 + quotedLength];
        response[0] = 0x45;
        response[2] = (byte) (response.length >>> 8);
        response[3] = (byte) response.length;
        response[8] = 64;
        response[9] = IPV4_PROTOCOL_ICMP;
        System.arraycopy(packet, 16, response, 12, 4);
        System.arraycopy(packet, 12, response, 16, 4);
        int icmpOffset = 20;
        response[icmpOffset] = ICMP_DESTINATION_UNREACHABLE;
        response[icmpOffset + 1] = ICMP_FRAGMENTATION_NEEDED;
        response[icmpOffset + 6] = (byte) (pathMtu >>> 8);
        response[icmpOffset + 7] = (byte) pathMtu;
        System.arraycopy(packet, 0, response, icmpOffset + 8, quotedLength);
        int icmpChecksum = checksum(response, icmpOffset, response.length - icmpOffset);
        response[icmpOffset + 2] = (byte) (icmpChecksum >>> 8);
        response[icmpOffset + 3] = (byte) icmpChecksum;
        int ipChecksum = checksum(response, 0, 20);
        response[10] = (byte) (ipChecksum >>> 8);
        response[11] = (byte) ipChecksum;
        return response;
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

    private static boolean hasValidIpv4Header(byte[] packet) {
        if (packet == null || packet.length < IPV4_MIN_HEADER_BYTES) {
            return false;
        }
        int version = (packet[0] >>> 4) & 0x0F;
        int ihl = packet[0] & 0x0F;
        return version == 4 && ihl >= 5 && packet.length >= ihl * 4;
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

    private static int tcpChecksum(byte[] packet, int tcpOffset, int tcpLength) {
        long sum = 0;
        for (int index = 12; index < 20; index += 2) {
            sum += ((packet[index] & 0xFF) << 8) | (packet[index + 1] & 0xFF);
        }
        sum += IPV4_PROTOCOL_TCP;
        sum += tcpLength;
        int index = tcpOffset;
        int end = tcpOffset + tcpLength;
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
