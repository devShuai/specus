package com.theshuai.tunnelclient.peer;

final class PeerIpPacket {
    private PeerIpPacket() {
    }

    static String destinationIpv4(byte[] packet) {
        if (packet == null || packet.length < 20) {
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
}
