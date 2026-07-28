package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerPathMtuTests {
    @Test
    void probeAndAckUseStrictAuthenticatedPayloadShape() throws IOException {
        JsonNode vector = readVector();
        long nonce = vector.path("nonce").asLong();
        int innerMtu = vector.path("innerMtu").asInt();
        byte[] probe = PeerPathMtu.probe(nonce, innerMtu);
        assertEquals(vector.path("probeLength").asInt(), probe.length);
        assertArrayEquals(HexFormat.of().parseHex(vector.path("probeHeaderHex").asText()),
                java.util.Arrays.copyOf(probe, 17));
        PeerPathMtu.Message decodedProbe = PeerPathMtu.decode(probe);
        assertNotNull(decodedProbe);
        assertTrue(decodedProbe.probe());
        assertEquals(nonce, decodedProbe.nonce());
        assertEquals(innerMtu, decodedProbe.innerMtu());

        byte[] ack = PeerPathMtu.ack(nonce, innerMtu);
        assertArrayEquals(HexFormat.of().parseHex(vector.path("ackHex").asText()), ack);
        PeerPathMtu.Message decodedAck = PeerPathMtu.decode(ack);
        assertNotNull(decodedAck);
        assertFalse(decodedAck.probe());
        assertNull(PeerPathMtu.decode(java.util.Arrays.copyOf(probe, probe.length - 1)));
    }

    private static JsonNode readVector() throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/peer-path-mtu-v2.json");
            if (Files.isRegularFile(candidate)) {
                return JsonUtil.readString(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate peer path MTU vector");
    }

    @Test
    void discoveryRetriesThenSearchesBelowABlackHole() {
        AtomicLong nonce = new AtomicLong(10);
        PeerPathMtu.Discovery discovery = new PeerPathMtu.Discovery();
        PeerPathMtu.Transition transition = discovery.activate(
                "direct|127.0.0.1:7000", 1280, null, 0, 1_000, nonce::incrementAndGet);
        assertEquals(1280, transition.probe().innerMtu());
        long firstNonce = transition.probe().nonce();

        assertEquals(1280, discovery.timeout(firstNonce, 2_000, nonce::incrementAndGet).probe().innerMtu());
        assertEquals(1280, discovery.timeout(firstNonce, 3_000, nonce::incrementAndGet).probe().innerMtu());
        PeerPathMtu.Transition reduced = discovery.timeout(firstNonce, 4_000, nonce::incrementAndGet);
        assertTrue(reduced.probe().innerMtu() < 1280);
        assertTrue(discovery.effectiveMtu(1280) < 1280);
    }

    @Test
    void successfulCeilingProbeIsCachedAtConfiguredMtu() {
        AtomicLong nonce = new AtomicLong(20);
        PeerPathMtu.Discovery discovery = new PeerPathMtu.Discovery();
        PeerPathMtu.Probe probe = discovery.activate(
                "relay|target", 1280, null, 0, 1_000, nonce::incrementAndGet).probe();
        PeerPathMtu.Transition complete = discovery.acknowledge(
                probe.nonce(), probe.innerMtu(), 1_050, nonce::incrementAndGet);
        assertEquals(1280, complete.completedMtu());
        assertEquals(1280, discovery.effectiveMtu(1280));
    }

    @Test
    void tcpMssAndPacketTooBigUseDiscoveredMtu() {
        byte[] syn = ipv4SynWithMss(1460);
        byte[] clamped = PeerIpPacket.clampTcpMss(syn, 1200);
        assertEquals(1160, ((clamped[42] & 0xFF) << 8) | (clamped[43] & 0xFF));

        byte[] ptb = PeerIpPacket.icmpFragmentationNeededFor(syn, 1200);
        assertNotNull(ptb);
        assertEquals(3, ptb[20] & 0xFF);
        assertEquals(4, ptb[21] & 0xFF);
        assertEquals(1200, ((ptb[26] & 0xFF) << 8) | (ptb[27] & 0xFF));
    }

    private static byte[] ipv4SynWithMss(int mss) {
        byte[] packet = new byte[44];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = 44;
        packet[8] = 64;
        packet[9] = 6;
        packet[12] = 100;
        packet[15] = 1;
        packet[16] = 100;
        packet[19] = 2;
        packet[32] = 0x60;
        packet[33] = 0x02;
        packet[40] = 2;
        packet[41] = 4;
        packet[42] = (byte) (mss >>> 8);
        packet[43] = (byte) mss;
        return packet;
    }
}
