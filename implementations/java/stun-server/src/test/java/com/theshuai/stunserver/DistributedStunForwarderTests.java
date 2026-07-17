package com.theshuai.stunserver;

import com.theshuai.common.stun.StunEndpointTopology;
import com.theshuai.common.stun.StunMessage;
import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DistributedStunForwarderTests {
    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-16T12:00:00Z"), ZoneOffset.UTC);
    private static final byte[] SECRET =
            "0123456789abcdef0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    @Test
    void authenticatesForwardedResponseAndRejectsReplay() throws Exception {
        StandaloneStunDistributionConfig primary = distribution(
                StunEndpointTopology.AddressSlot.PRIMARY,
                "127.0.0.1",
                "127.0.0.2");
        StandaloneStunDistributionConfig alternate = distribution(
                StunEndpointTopology.AddressSlot.ALTERNATE,
                "127.0.0.2",
                "127.0.0.1");
        DistributedStunForwarder sender =
                new DistributedStunForwarder(primary, CLOCK, new SecureRandom());
        DistributedStunForwarder receiver =
                new DistributedStunForwarder(alternate, CLOCK, new SecureRandom());
        StunMessage response = StunMessage.of(
                StunMessage.BINDING_SUCCESS,
                StunMessage.newTransactionId(),
                StunMessage.software("test"));
        InetSocketAddress target = address("198.51.100.25", 54_321);

        byte[] encoded = sender.encode(
                StunEndpointTopology.ALTERNATE,
                target,
                response.toBytes());
        DatagramPacket packet = packetFrom(encoded, primary.controlBindAddress());
        DistributedStunForwarder.DecodeResult decoded = receiver.decode(packet);

        assertTrue(decoded.accepted());
        assertEquals(StunEndpointTopology.ALTERNATE,
                decoded.response().responseEndpoint());
        assertEquals(target, decoded.response().responseTarget());
        assertArrayEquals(response.toBytes(), decoded.response().response());

        DistributedStunForwarder.DecodeResult replay = receiver.decode(packet);
        assertFalse(replay.accepted());
        assertEquals("replay", replay.rejectionReason());
    }

    @Test
    void rejectsTamperingAndExpiredForwardPackets() throws Exception {
        StandaloneStunDistributionConfig primary = distribution(
                StunEndpointTopology.AddressSlot.PRIMARY,
                "127.0.0.1",
                "127.0.0.2");
        StandaloneStunDistributionConfig alternate = distribution(
                StunEndpointTopology.AddressSlot.ALTERNATE,
                "127.0.0.2",
                "127.0.0.1");
        DistributedStunForwarder sender =
                new DistributedStunForwarder(primary, CLOCK, new SecureRandom());
        StunMessage response = StunMessage.of(
                StunMessage.BINDING_SUCCESS,
                StunMessage.newTransactionId(),
                StunMessage.software("test"));
        byte[] encoded = sender.encode(
                StunEndpointTopology.ALTERNATE_PRIMARY_PORT,
                address("198.51.100.25", 54_321),
                response.toBytes());

        byte[] tampered = Arrays.copyOf(encoded, encoded.length);
        tampered[tampered.length - 1] ^= 1;
        DistributedStunForwarder receiver =
                new DistributedStunForwarder(alternate, CLOCK, new SecureRandom());
        DistributedStunForwarder.DecodeResult badHmac =
                receiver.decode(packetFrom(tampered, primary.controlBindAddress()));
        assertFalse(badHmac.accepted());
        assertEquals("bad_hmac", badHmac.rejectionReason());

        Clock expiredClock = Clock.offset(CLOCK, java.time.Duration.ofSeconds(31));
        DistributedStunForwarder expiredReceiver =
                new DistributedStunForwarder(alternate, expiredClock, new SecureRandom());
        DistributedStunForwarder.DecodeResult stale =
                expiredReceiver.decode(packetFrom(encoded, primary.controlBindAddress()));
        assertFalse(stale.accepted());
        assertEquals("stale", stale.rejectionReason());
    }

    private static StandaloneStunDistributionConfig distribution(
            StunEndpointTopology.AddressSlot slot,
            String bind,
            String peer) throws Exception {
        return new StandaloneStunDistributionConfig(
                true,
                slot,
                address(bind, 3480),
                address(peer, 3480),
                SECRET,
                30,
                128,
                4_096,
                100,
                200);
    }

    private static DatagramPacket packetFrom(byte[] bytes, InetSocketAddress source) {
        return new DatagramPacket(bytes, bytes.length, source);
    }

    private static InetSocketAddress address(String host, int port) throws Exception {
        return new InetSocketAddress(InetAddress.getByName(host), port);
    }
}
