package com.theshuai.common.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebSocketSpecusFrameTests {
    @Test
    void matchesCentralSws2Vector() throws IOException {
        JsonNode vector = JsonUtil.readString(Files.readString(findVector())).path("webSocket");
        byte[] expected = HexFormat.of().parseHex(vector.path("frameHex").asText());
        WebSocketSpecusFrame frame = new WebSocketSpecusFrame(
                vector.path("opcode").asInt(),
                vector.path("finalFragment").asBoolean(),
                vector.path("rsv").asInt(),
                vector.path("closeCode").asInt(),
                vector.path("payloadUtf8").asText().getBytes(StandardCharsets.UTF_8));

        assertArrayEquals(expected, frame.encode());
        assertArrayEquals(frame.payload(), WebSocketSpecusFrame.decode(expected).payload());
        assertThrows(IllegalArgumentException.class, () -> WebSocketSpecusFrame.decode(
                HexFormat.of().parseHex(vector.path("invalidMagicHex").asText())));
        assertThrows(IllegalArgumentException.class, () -> WebSocketSpecusFrame.decode(
                HexFormat.of().parseHex(vector.path("truncatedHex").asText())));
        assertThrows(IllegalArgumentException.class, () -> WebSocketSpecusFrame.decode(
                HexFormat.of().parseHex(vector.path("trailingHex").asText())));

        for (JsonNode code : vector.path("wireForbiddenCloseCodes")) {
            int closeCode = code.asInt();
            assertThrows(IllegalArgumentException.class, () -> new WebSocketSpecusFrame(
                    WebSocketSpecusFrame.OPCODE_CLOSE, true, 0, closeCode, new byte[0]));

            byte[] wireFrame = closeFrame(closeCode);
            assertThrows(IllegalArgumentException.class, () -> WebSocketSpecusFrame.decode(wireFrame));
        }
    }

    @Test
    void roundTripsCloseFrame() {
        byte[] reason = "going away".getBytes(StandardCharsets.UTF_8);
        WebSocketSpecusFrame decoded = WebSocketSpecusFrame.decode(new WebSocketSpecusFrame(
                WebSocketSpecusFrame.OPCODE_CLOSE, true, 0, 1001, reason).encode());

        assertEquals(WebSocketSpecusFrame.OPCODE_CLOSE, decoded.opcode());
        assertTrue(decoded.finalFragment());
        assertEquals(1001, decoded.closeCode());
        assertArrayEquals(reason, decoded.payload());
    }

    @Test
    void rejectsLegacyPrefixAndTrailingBytes() {
        assertThrows(IllegalArgumentException.class,
                () -> WebSocketSpecusFrame.decode(new byte[]{0x01, 'o', 'l', 'd'}));
        byte[] valid = new WebSocketSpecusFrame(
                WebSocketSpecusFrame.OPCODE_BINARY, true, 0, 0, new byte[]{1, 2}).encode();
        byte[] trailing = java.util.Arrays.copyOf(valid, valid.length + 1);
        assertThrows(IllegalArgumentException.class, () -> WebSocketSpecusFrame.decode(trailing));
    }

    private static byte[] closeFrame(int closeCode) {
        return ByteBuffer.allocate(WebSocketSpecusFrame.HEADER_BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(WebSocketSpecusFrame.MAGIC)
                .put((byte) WebSocketSpecusFrame.OPCODE_CLOSE)
                .put((byte) 1)
                .putShort((short) closeCode)
                .putInt(0)
                .array();
    }

    private static Path findVector() {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 6; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/application-protocol-v2.json");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("cannot locate application protocol v2 vector");
    }
}
