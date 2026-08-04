package com.theshuai.specus.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class PeerUdpProbeCodecTest {
    @Test
    public void decodesOnlyBoundedPlausibleProbePackets() {
        byte[] json = ("{\"magic\":\"specus-peer-mesh\",\"type\":\"check\",\"sessionId\":7,"
                + "\"fromClientId\":11,\"toClientId\":22,\"nonce\":\"abc\","
                + "\"token\":\"token\",\"sentAtMillis\":123}")
                .getBytes(StandardCharsets.UTF_8);
        byte[] packet = new byte[json.length + 8];
        System.arraycopy(json, 0, packet, 4, json.length);

        JSONObject probe = PeerUdpProbeCodec.decode(packet, 4, json.length);

        assertNotNull(probe);
        assertEquals("check", probe.optString("type"));
        assertEquals(7L, probe.optLong("sessionId"));

        byte[] malformed = "{\"magic\":\"specus-peer-mesh\",\"toClientId\":oops}"
                .getBytes(StandardCharsets.UTF_8);
        byte[] wrongMagic = "{\"magic\":\"other\"}".getBytes(StandardCharsets.UTF_8);
        byte[] oversized = new byte[PeerUdpProbeCodec.MAX_PACKET_BYTES + 1];
        oversized[0] = '{';
        oversized[oversized.length - 1] = '}';
        assertNull(PeerUdpProbeCodec.decode(malformed, 0, malformed.length));
        assertNull(PeerUdpProbeCodec.decode(wrongMagic, 0, wrongMagic.length));
        assertNull(PeerUdpProbeCodec.decode(oversized, 0, oversized.length));
    }

    @Test
    public void limitsPerSourceAndAggregateProbeRates() throws Exception {
        PeerUdpProbeRateLimiter limiter = new PeerUdpProbeRateLimiter();
        InetAddress oneSource = InetAddress.getByName("192.0.2.10");
        for (int index = 0; index < 100; index++) {
            assertTrue(limiter.tryAcquire(oneSource, 10_000L));
        }
        assertFalse(limiter.tryAcquire(oneSource, 10_000L));
        assertTrue(limiter.tryAcquire(oneSource, 11_000L));

        PeerUdpProbeRateLimiter aggregate = new PeerUdpProbeRateLimiter();
        for (int sourceIndex = 1; sourceIndex <= 20; sourceIndex++) {
            InetAddress source = InetAddress.getByName("198.51.100." + sourceIndex);
            for (int packetIndex = 0; packetIndex < 100; packetIndex++) {
                assertTrue(aggregate.tryAcquire(source, 20_000L));
            }
        }
        assertFalse(aggregate.tryAcquire(InetAddress.getByName("198.51.100.21"), 20_000L));
    }

    @Test
    public void validatesProbeTargetTypesAndExpectedEndpoint() throws Exception {
        JSONObject probe = new JSONObject()
                .put("magic", "specus-peer-mesh")
                .put("type", "check-response")
                .put("sessionId", 7L)
                .put("fromClientId", 11L)
                .put("toClientId", 22L)
                .put("nonce", "abc")
                .put("token", "token")
                .put("sentAtMillis", 123L);
        assertTrue(PeerMeshEngine.validProbeEnvelope(probe, 22L));
        assertFalse(PeerMeshEngine.validProbeEnvelope(probe, 23L));
        probe.put("sessionId", 7.5d);
        assertFalse(PeerMeshEngine.validProbeEnvelope(probe, 22L));
        probe.put("sessionId", 7L).put("token", 123L);
        assertFalse(PeerMeshEngine.validProbeEnvelope(probe, 22L));

        InetSocketAddress direct = new InetSocketAddress(InetAddress.getByName("192.0.2.20"), 40_000);
        InetSocketAddress other = new InetSocketAddress(InetAddress.getByName("192.0.2.21"), 40_000);
        assertTrue(PeerMeshEngine.probeEndpointMatches(
                false, direct, "", null, direct, ""));
        assertFalse(PeerMeshEngine.probeEndpointMatches(
                false, direct, "", null, other, ""));

        InetSocketAddress turn = new InetSocketAddress(InetAddress.getByName("198.51.100.10"), 3478);
        assertTrue(PeerMeshEngine.probeEndpointMatches(
                true, null, "203.0.113.8:50000", turn, turn, "turn:203.0.113.8:50000"));
        assertFalse(PeerMeshEngine.probeEndpointMatches(
                true, null, "203.0.113.8:50000", turn, turn, "203.0.113.8:50001"));
        assertFalse(PeerMeshEngine.probeEndpointMatches(
                true, null, "203.0.113.8:50000", turn, other, "203.0.113.8:50000"));
    }
}
