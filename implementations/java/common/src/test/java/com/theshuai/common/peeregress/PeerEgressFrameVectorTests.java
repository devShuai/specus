package com.theshuai.common.peeregress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Replays {@code peer-egress-frame-v1.json} against the Java SPEG1 codec.
 *
 * <p>The rejection cases assert the returned code and not merely that the frame was refused: an
 * operator who only sees "rejected" cannot tell a malformed frame from an unsupported one.
 */
class PeerEgressFrameVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private static JsonNode readVector(String name) throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve(name);
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate " + name);
    }

    @Test
    void acceptedFramesMatchSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-frame-v1.json");
        JsonNode accept = vector.get("accept");
        assertTrue(accept != null && accept.size() > 0, "frame vector carried no accept cases");

        for (JsonNode testCase : accept) {
            String name = testCase.get("name").asText();
            byte[] raw = HEX.parseHex(testCase.get("frameHex").asText());

            assertTrue(PeerEgressFrame.looksLikeFrame(raw), name + ": not recognised as SPEG1");
            PeerEgressFrame.Decoded decoded = PeerEgressFrame.parse(raw);
            assertNull(decoded.code(), name + ": refused with " + decoded.code());
            assertEquals(testCase.get("type").asInt(), decoded.type(), name + ": type");
            assertEquals(
                    (testCase.path("flags").asInt(0) & PeerEgressFrame.FLAG_HOP) != 0,
                    decoded.hop(),
                    name + ": hop");

            String innerHex = testCase.path("innerPacketHex").asText("");
            if (innerHex.isEmpty()) {
                continue;
            }
            assertEquals(innerHex, HEX.formatHex(decoded.body()), name + ": body");
            assertEquals(
                    testCase.get("innerSourceIp").asText(),
                    decoded.inner().sourceIp(),
                    name + ": inner source");
            assertEquals(
                    testCase.get("innerDestinationIp").asText(),
                    decoded.inner().destinationIp(),
                    name + ": inner destination");
            assertEquals(
                    testCase.path("innerSourcePort").asInt(0),
                    decoded.inner().sourcePort(),
                    name + ": inner source port");
            assertEquals(
                    testCase.path("innerDestinationPort").asInt(0),
                    decoded.inner().destinationPort(),
                    name + ": inner destination port");

            String protocol = testCase.path("innerProtocol").asText("");
            if ("tcp".equals(protocol)) {
                assertEquals(6, decoded.inner().protocol(), name + ": inner protocol");
            } else if ("udp".equals(protocol)) {
                assertEquals(17, decoded.inner().protocol(), name + ": inner protocol");
            }
        }
    }

    @Test
    void rejectedFramesMatchSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-frame-v1.json");
        JsonNode reject = vector.get("reject");
        assertTrue(reject != null && reject.size() > 0, "frame vector carried no reject cases");

        for (JsonNode testCase : reject) {
            String name = testCase.get("name").asText();
            byte[] raw = HEX.parseHex(testCase.get("frameHex").asText());
            PeerEgressFrame.Decoded decoded = PeerEgressFrame.parse(raw);
            assertEquals(testCase.get("code").asText(), decoded.code(), name + ": code");
            assertFalse(decoded.accepted(), name + ": was accepted");
        }
    }

    /**
     * A round trip through the encoder has to come back out of the parser. Otherwise the two halves
     * could each be self-consistently wrong.
     */
    @Test
    void encodedFramesParseBack() throws IOException {
        JsonNode vector = readVector("peer-egress-frame-v1.json");
        for (JsonNode testCase : vector.get("accept")) {
            String innerHex = testCase.path("innerPacketHex").asText("");
            if (innerHex.isEmpty()) {
                continue;
            }
            byte[] body = HEX.parseHex(innerHex);
            byte[] frame = PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false, body);
            assertEquals(testCase.get("frameHex").asText(), HEX.formatHex(frame),
                    testCase.get("name").asText() + ": re-encoded frame");
        }
    }

    /**
     * The hop flag is refused at the frame layer, before anything looks at the packet inside it.
     * There are no multi-hop egress chains, and a frame that claims one must not reach the
     * authorization step at all.
     */
    @Test
    void hopFlaggedFramesAreRefusedBeforeTheBodyIsRead() {
        byte[] frame = PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, true, new byte[] {0x01});
        PeerEgressFrame.Decoded decoded = PeerEgressFrame.parse(frame);
        assertEquals(PeerEgressCodes.HOP_NOT_ALLOWED, decoded.code());
    }

    /** A payload that is not SPEG1 at all is left for the mesh's own handling. */
    @Test
    void nonFramePayloadsAreNotClaimed() {
        assertFalse(PeerEgressFrame.looksLikeFrame(null));
        assertFalse(PeerEgressFrame.looksLikeFrame(new byte[0]));
        assertFalse(PeerEgressFrame.looksLikeFrame(new byte[] {0x45, 0x00, 0x00, 0x28}));
    }
}
