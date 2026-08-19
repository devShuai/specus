package com.theshuai.specus.android;

import org.json.JSONObject;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * The three codecs that parse bytes an attacker can choose.
 *
 * <p>Every one of these decodes a UDP payload or a peer frame that arrives off the network before
 * anything has authenticated it, so the input is entirely under a hostile party's control. A
 * decoder that throws an unexpected exception, or that returns a half-built object the caller then
 * trusts, turns a malformed packet into a crash or worse. These feed each of them truncated,
 * oversized, structurally wrong and randomly fuzzed input, and require the same thing every time:
 * either a clean rejection, or a value the caller can safely use — never an unchecked throw.
 */
public class MalformedFrameTest {
    /** Inputs that are wrong in structurally different ways, reused across every decoder. */
    private static byte[][] hostileInputs() {
        return new byte[][]{
                new byte[0],
                new byte[]{0},
                new byte[]{(byte) 0xFF},
                new byte[]{1, 2, 3},
                new byte[]{(byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80},
                "not a frame at all".getBytes(StandardCharsets.UTF_8),
                "{".getBytes(StandardCharsets.UTF_8),
                "{\"unterminated\":".getBytes(StandardCharsets.UTF_8),
                "[]".getBytes(StandardCharsets.UTF_8),
                new byte[64 * 1024],
        };
    }

    @Test
    public void peerAppMessageCodecRejectsHostileInput() {
        for (byte[] input : hostileInputs()) {
            // looksLike is the gate the caller uses; it must answer rather than throw.
            boolean claimed = PeerAppMessageCodec.looksLike(input);
            PeerAppMessageCodec.PeerAppMessage decoded = PeerAppMessageCodec.decode(input);
            if (claimed) {
                // Claiming a payload and then returning null is allowed; throwing is not.
                continue;
            }
            assertNull("a payload the codec does not claim must not decode: " + describe(input),
                    decoded);
        }
        assertFalse(PeerAppMessageCodec.looksLike(null));
        assertNull(PeerAppMessageCodec.decode(null));
    }

    @Test
    public void peerPathMtuRejectsHostileInput() {
        for (byte[] input : hostileInputs()) {
            boolean claimed = PeerPathMtu.looksLike(input);
            PeerPathMtu.Message decoded = PeerPathMtu.decode(input);
            if (!claimed) {
                assertNull("a payload PeerPathMtu does not claim must not decode: " + describe(input),
                        decoded);
            }
        }
        assertFalse(PeerPathMtu.looksLike(null));
        assertNull(PeerPathMtu.decode(null));
    }

    @Test
    public void peerUdpProbeCodecRejectsHostileInput() {
        for (byte[] input : hostileInputs()) {
            JSONObject decoded = PeerUdpProbeCodec.decode(input, 0, input.length);
            // Whatever comes back, it must not have thrown; a null is a clean rejection.
            if (decoded != null) {
                assertNotNull(decoded.toString());
            }
        }
        assertNull(PeerUdpProbeCodec.decode(null, 0, 0));
    }

    /**
     * Offsets and lengths arrive from frame headers, so they are attacker-chosen too. A decoder
     * that indexes with them unchecked reads out of bounds on a crafted packet.
     */
    @Test
    public void peerUdpProbeCodecRejectsOutOfRangeSlices() {
        byte[] packet = "{\"type\":\"probe\"}".getBytes(StandardCharsets.UTF_8);

        // Each of these describes a slice that is not inside the packet.
        PeerUdpProbeCodec.decode(packet, -1, packet.length);
        PeerUdpProbeCodec.decode(packet, 0, packet.length + 100);
        PeerUdpProbeCodec.decode(packet, packet.length, 1);
        PeerUdpProbeCodec.decode(packet, packet.length + 5, 1);
        PeerUdpProbeCodec.decode(packet, 0, -1);
        PeerUdpProbeCodec.decode(packet, Integer.MAX_VALUE, Integer.MAX_VALUE);
        // Reaching here without an exception is the assertion.
    }

    /**
     * A well-formed frame with one byte flipped is the case a length or magic check alone misses,
     * and it is what a real attacker produces by mutating a captured packet.
     */
    @Test
    public void singleByteMutationsOfValidFramesNeverThrow() {
        byte[] valid = PeerPathMtu.probe(0x0123456789ABCDEFL, 1280);
        assertTrue("precondition: the generated probe must be recognised",
                PeerPathMtu.looksLike(valid));

        for (int index = 0; index < valid.length; index++) {
            for (int mutation : new int[]{0x01, 0x7F, 0xFF}) {
                byte[] corrupted = valid.clone();
                corrupted[index] = (byte) (corrupted[index] ^ mutation);
                PeerPathMtu.looksLike(corrupted);
                PeerPathMtu.decode(corrupted);
            }
        }
    }

    /**
     * A truncated frame is what a path MTU drop or a half-written buffer produces, so it is a
     * fault-injection case as much as an attack one.
     */
    @Test
    public void truncationAtEveryLengthNeverThrows() {
        byte[] valid = PeerPathMtu.ack(42L, 1200);

        for (int length = 0; length < valid.length; length++) {
            byte[] truncated = new byte[length];
            System.arraycopy(valid, 0, truncated, 0, length);
            PeerPathMtu.looksLike(truncated);
            PeerPathMtu.decode(truncated);
        }
    }

    /** A fixed seed keeps a failure reproducible; a random one would report a different case each run. */
    @Test
    public void randomPayloadsNeverThrow() {
        Random random = new Random(20260819L);

        for (int iteration = 0; iteration < 2000; iteration++) {
            byte[] payload = new byte[random.nextInt(96)];
            random.nextBytes(payload);

            PeerAppMessageCodec.looksLike(payload);
            PeerAppMessageCodec.decode(payload);
            PeerPathMtu.looksLike(payload);
            PeerPathMtu.decode(payload);
            PeerUdpProbeCodec.decode(payload, 0, payload.length);
        }
    }

    private static String describe(byte[] input) {
        return input.length + " bytes";
    }
}
