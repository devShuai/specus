package com.theshuai.common.peermesh;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerDataFrameHeaderTests {
    @Test
    void shouldParseStrictSpm2FrameAndRejectZeroSequence() throws IOException {
        JsonNode vector = readVector();
        byte[] frame = HexFormat.of().parseHex(vector.path("frameHex").asText());

        assertEquals(new PeerDataFrameHeader(
                vector.path("sessionId").asLong(), vector.path("sequence").asLong()),
                PeerDataFrameHeader.parse(frame));
        assertTrue(PeerDataFrameHeader.looksLikeDataFrame(frame));

        Arrays.fill(frame, 12, 20, (byte) 0);
        assertNull(PeerDataFrameHeader.parse(frame));
    }

    private static JsonNode readVector() throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/peer-mesh-spm2.json");
            if (Files.isRegularFile(candidate)) {
                return JsonUtil.readString(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate peer-mesh-spm2.json");
    }

    @Test
    void shouldRejectRemovedSpm1Frame() {
        byte[] frame = ByteBuffer.allocate(70).putInt(0x53504D31).array();

        assertFalse(PeerDataFrameHeader.looksLikeDataFrame(frame));
        assertNull(PeerDataFrameHeader.parse(frame));
    }
}
