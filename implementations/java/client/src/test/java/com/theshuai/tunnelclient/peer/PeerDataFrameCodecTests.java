package com.theshuai.tunnelclient.peer;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerDataFrameCodecTests {

    @Test
    void shouldEncodeAndDecodeEncryptedFrame() {
        byte[] key = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        byte[] payload = {0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 100, 96, 0, 1, 100, 96, 0, 2};

        byte[] packet = PeerDataFrameCodec.encode(key, 99L, 1L, 2L, 7L, payload);
        PeerDataFrame frame = PeerDataFrameCodec.decode(key, packet, 99L, 2L);

        assertEquals(99L, PeerDataFrameCodec.sessionId(packet));
        assertNotNull(frame);
        assertEquals(99L, frame.sessionId());
        assertEquals(1L, frame.fromClientId());
        assertEquals(2L, frame.toClientId());
        assertEquals(7L, frame.sequence());
        assertArrayEquals(payload, frame.plaintext());
        assertTrue(PeerDataFrameCodec.looksLikeDataFrame(packet, 0, packet.length));
    }

    @Test
    void shouldRejectFrameForWrongReceiver() {
        byte[] key = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        byte[] packet = PeerDataFrameCodec.encode(key, 99L, 1L, 2L, 7L, new byte[]{1, 2, 3});

        assertNull(PeerDataFrameCodec.decode(key, packet, 99L, 3L));
    }

    @Test
    void shouldNotReadSessionIdFromMalformedFrame() {
        assertNull(PeerDataFrameCodec.sessionId(new byte[]{1, 2, 3}));
    }

    @Test
    void shouldExtractIpv4DestinationAddress() {
        byte[] packet = {0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 100, 96, 0, 1, 100, 96, 0, 2};

        assertEquals("100.96.0.2", PeerIpPacket.destinationIpv4(packet));
    }
}
