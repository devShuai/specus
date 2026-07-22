package com.theshuai.tunnelclient.peer;

import com.theshuai.common.peermesh.PeerUdpProbe;
import com.theshuai.common.util.JsonUtil;

import java.nio.charset.StandardCharsets;

final class PeerUdpProbeCodec {
    static final int MAX_PACKET_BYTES = 2_048;
    private static final byte[] MAGIC = PeerUdpProbe.MAGIC.getBytes(StandardCharsets.US_ASCII);

    private PeerUdpProbeCodec() {
    }

    static PeerUdpProbe decode(byte[] packet, int offset, int length) {
        if (!looksPlausible(packet, offset, length)) {
            return null;
        }
        PeerUdpProbe probe = JsonUtil.bytesToObjectQuietly(packet, offset, length, PeerUdpProbe.class);
        return probe != null && PeerUdpProbe.MAGIC.equals(probe.getMagic()) ? probe : null;
    }

    private static boolean looksPlausible(byte[] packet, int offset, int length) {
        if (packet == null
                || offset < 0
                || length < MAGIC.length + 8
                || length > MAX_PACKET_BYTES
                || offset > packet.length - length
                || packet[offset] != '{'
                || packet[offset + length - 1] != '}') {
            return false;
        }
        int searchEnd = Math.min(offset + length, offset + 160);
        outer:
        for (int index = offset; index <= searchEnd - MAGIC.length; index++) {
            for (int magicIndex = 0; magicIndex < MAGIC.length; magicIndex++) {
                if (packet[index + magicIndex] != MAGIC[magicIndex]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
