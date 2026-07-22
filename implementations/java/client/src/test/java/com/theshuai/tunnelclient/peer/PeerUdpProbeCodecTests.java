package com.theshuai.tunnelclient.peer;

import com.theshuai.common.peermesh.PeerUdpProbe;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class PeerUdpProbeCodecTests {

    @Test
    void decodesValidProbeFromPacketRange() {
        byte[] json = ("{\"magic\":\"shuai-peer-mesh\",\"type\":\"check\",\"sessionId\":7,"
                + "\"fromClientId\":11,\"toClientId\":22,\"nonce\":\"abc\"}")
                .getBytes(StandardCharsets.UTF_8);
        byte[] packet = new byte[json.length + 8];
        System.arraycopy(json, 0, packet, 4, json.length);

        PeerUdpProbe probe = PeerUdpProbeCodec.decode(packet, 4, json.length);

        assertThat(probe).isNotNull();
        assertThat(probe.getType()).isEqualTo(PeerUdpProbe.TYPE_CHECK);
        assertThat(probe.getSessionId()).isEqualTo(7L);
        assertThat(probe.getToClientId()).isEqualTo(22L);
    }

    @Test
    void rejectsMalformedWrongMagicAndOversizedPackets() {
        byte[] malformed = "{\"magic\":\"shuai-peer-mesh\",\"toClientId\":oops}"
                .getBytes(StandardCharsets.UTF_8);
        byte[] wrongMagic = "{\"magic\":\"not-peer-mesh\"}".getBytes(StandardCharsets.UTF_8);
        byte[] oversized = new byte[PeerUdpProbeCodec.MAX_PACKET_BYTES + 1];
        oversized[0] = '{';
        oversized[oversized.length - 1] = '}';

        assertThat(PeerUdpProbeCodec.decode(malformed, 0, malformed.length)).isNull();
        assertThat(PeerUdpProbeCodec.decode(wrongMagic, 0, wrongMagic.length)).isNull();
        assertThat(PeerUdpProbeCodec.decode(oversized, 0, oversized.length)).isNull();
    }

    @Test
    void limitsEachSourceAndResetsAfterWindow() throws Exception {
        PeerUdpProbeRateLimiter limiter = new PeerUdpProbeRateLimiter();
        InetAddress source = InetAddress.getByName("192.0.2.10");

        for (int index = 0; index < 100; index++) {
            assertThat(limiter.tryAcquire(source, 10_000)).isTrue();
        }
        assertThat(limiter.tryAcquire(source, 10_000)).isFalse();
        assertThat(limiter.tryAcquire(source, 11_000)).isTrue();
    }

    @Test
    void limitsAggregateProbeRate() throws Exception {
        PeerUdpProbeRateLimiter limiter = new PeerUdpProbeRateLimiter();

        for (int sourceIndex = 1; sourceIndex <= 20; sourceIndex++) {
            InetAddress source = InetAddress.getByName("198.51.100." + sourceIndex);
            for (int packetIndex = 0; packetIndex < 100; packetIndex++) {
                assertThat(limiter.tryAcquire(source, 20_000)).isTrue();
            }
        }

        assertThat(limiter.tryAcquire(InetAddress.getByName("198.51.100.21"), 20_000)).isFalse();
    }
}
