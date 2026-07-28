package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerAppMessageCodecTests {
    @Test
    void matchesCentralStmsg2Vector() throws IOException {
        JsonNode vector = JsonUtil.readString(Files.readString(findVector())).path("clientMessage");
        PeerAppMessageCodec.PeerAppMessage message = new PeerAppMessageCodec.PeerAppMessage();
        message.setType(vector.path("type").asText());
        message.setId(vector.path("id").asText());
        message.setFromClientId(vector.path("fromClientId").asLong());
        message.setFromClientName(vector.path("fromClientName").asText());
        message.setToClientId(vector.path("toClientId").asLong());
        message.setToClientName(vector.path("toClientName").asText());
        message.setMessage(vector.path("message").asText());
        message.setCreatedAtMillis(vector.path("createdAtMillis").asLong());

        byte[] expected = HexFormat.of().parseHex(vector.path("payloadHex").asText());
        assertArrayEquals(expected, PeerAppMessageCodec.encode(message));
        PeerAppMessageCodec.PeerAppMessage decoded = PeerAppMessageCodec.decode(expected);
        assertNotNull(decoded);
        assertEquals(message.getType(), decoded.getType());
        assertEquals(message.getId(), decoded.getId());
        assertEquals(message.getFromClientId(), decoded.getFromClientId());
        assertEquals(message.getFromClientName(), decoded.getFromClientName());
        assertEquals(message.getToClientId(), decoded.getToClientId());
        assertEquals(message.getToClientName(), decoded.getToClientName());
        assertEquals(message.getMessage(), decoded.getMessage());
        assertEquals(message.getCreatedAtMillis(), decoded.getCreatedAtMillis());
    }

    @Test
    void encodesMandatoryStmsg2() {
        PeerAppMessageCodec.PeerAppMessage message = new PeerAppMessageCodec.PeerAppMessage();
        message.setType(PeerAppMessageCodec.TYPE_MESSAGE);
        message.setId("message-1");
        message.setMessage("hello");

        byte[] encoded = PeerAppMessageCodec.encode(message);
        assertTrue(new String(encoded, 0, 7, StandardCharsets.US_ASCII).equals("STMSG2\n"));
        PeerAppMessageCodec.PeerAppMessage decoded = PeerAppMessageCodec.decode(encoded);
        assertNotNull(decoded);
        assertEquals("message-1", decoded.getId());
        assertEquals("hello", decoded.getMessage());
    }

    @Test
    void rejectsRemovedStmsg1() {
        byte[] legacy = "STMSG1\n{\"type\":\"message\"}".getBytes(StandardCharsets.UTF_8);
        assertFalse(PeerAppMessageCodec.looksLike(legacy));
        assertEquals(null, PeerAppMessageCodec.decode(legacy));
    }

    private static Path findVector() {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/application-protocol-v2.json");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("cannot locate application protocol v2 vector");
    }
}
