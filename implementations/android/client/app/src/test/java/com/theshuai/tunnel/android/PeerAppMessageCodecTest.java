package com.theshuai.tunnel.android;

import org.json.JSONObject;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class PeerAppMessageCodecTest {
    @Test
    public void matchesCentralStmsg2Vector() throws Exception {
        JSONObject vector = new JSONObject(new String(
                Files.readAllBytes(findVector()), StandardCharsets.UTF_8)).getJSONObject("clientMessage");
        PeerAppMessageCodec.PeerAppMessage message = new PeerAppMessageCodec.PeerAppMessage();
        message.type = vector.getString("type");
        message.id = vector.getString("id");
        message.fromClientId = vector.getLong("fromClientId");
        message.fromClientName = vector.getString("fromClientName");
        message.toClientId = vector.getLong("toClientId");
        message.toClientName = vector.getString("toClientName");
        message.message = vector.getString("message");
        message.createdAtMillis = vector.getLong("createdAtMillis");

        byte[] expected = HexFormat.of().parseHex(vector.getString("payloadHex"));
        org.junit.Assert.assertArrayEquals(expected, PeerAppMessageCodec.encode(message));
        PeerAppMessageCodec.PeerAppMessage decoded = PeerAppMessageCodec.decode(expected);
        assertNotNull(decoded);
        assertEquals(message.type, decoded.type);
        assertEquals(message.id, decoded.id);
        assertEquals(message.fromClientId, decoded.fromClientId);
        assertEquals(message.fromClientName, decoded.fromClientName);
        assertEquals(message.toClientId, decoded.toClientId);
        assertEquals(message.toClientName, decoded.toClientName);
        assertEquals(message.message, decoded.message);
        assertEquals(message.createdAtMillis, decoded.createdAtMillis);
    }

    @Test
    public void ordinaryTextUsesMandatoryStmsg2WireFormat() throws Exception {
        PeerAppMessageCodec.PeerAppMessage message = new PeerAppMessageCodec.PeerAppMessage();
        message.type = PeerAppMessageCodec.TYPE_MESSAGE;
        message.id = "message-1";
        message.fromClientId = 1L;
        message.fromClientName = "android-a";
        message.toClientId = 2L;
        message.toClientName = "desktop-b";
        message.message = "hello";
        message.createdAtMillis = 1234L;

        byte[] payload = PeerAppMessageCodec.encode(message);

        assertEquals("STMSG2\n", new String(payload, 0, 7, StandardCharsets.US_ASCII));
        PeerAppMessageCodec.PeerAppMessage decoded = PeerAppMessageCodec.decode(payload);
        assertNotNull(decoded);
        assertEquals("message-1", decoded.id);
        assertEquals("hello", decoded.message);
        assertNull(decoded.attachment);
    }

    @Test
    public void stmsg2AttachmentRoundTripsWithAllTransferMetadata() throws Exception {
        PeerAppMessageCodec.PeerAppMessage message = new PeerAppMessageCodec.PeerAppMessage();
        message.type = PeerAppMessageCodec.TYPE_MESSAGE;
        message.id = "msg-1";
        message.fromClientId = 1L;
        message.fromClientName = "android-a";
        message.toClientId = 2L;
        message.toClientName = "desktop-b";
        message.message = "report";
        message.attachment = new JSONObject()
                .put("objectId", "obj-1")
                .put("attachmentId", 22L)
                .put("fileName", "report.pdf")
                .put("mimeType", "application/pdf")
                .put("sizeBytes", 4096L)
                .put("sha256", "abc123");
        message.createdAtMillis = 1780000000000L;

        byte[] encoded = PeerAppMessageCodec.encode(message);
        assertTrue(new String(encoded, 0, 7, StandardCharsets.US_ASCII).equals("STMSG2\n"));
        PeerAppMessageCodec.PeerAppMessage decoded = PeerAppMessageCodec.decode(encoded);
        assertNotNull(decoded);
        assertEquals("msg-1", decoded.id);
        assertEquals("report", decoded.message);
        assertEquals("obj-1", decoded.attachment.getString("objectId"));
        assertEquals(22L, decoded.attachment.getLong("attachmentId"));
        assertEquals("report.pdf", decoded.attachment.getString("fileName"));
        assertEquals("application/pdf", decoded.attachment.getString("mimeType"));
        assertEquals(4096L, decoded.attachment.getLong("sizeBytes"));
        assertEquals("abc123", decoded.attachment.getString("sha256"));
        assertEquals("report [附件] report.pdf · application/pdf · 4.0 KB",
                PeerAppMessageCodec.displayText(decoded));
    }

    @Test
    public void removedStmsg1PayloadIsRejected() throws Exception {
        byte[] payload = ("STMSG1\n" + new JSONObject()
                .put("type", "message")
                .put("id", "old")
                .put("fromClientId", 7L)
                .put("fromClientName", "java-or-go")
                .put("toClientId", 8L)
                .put("toClientName", "android")
                .put("message", "legacy")
                .put("createdAtMillis", 4567L)
                .toString()).getBytes(StandardCharsets.UTF_8);

        assertFalse(PeerAppMessageCodec.looksLike(payload));
        assertNull(PeerAppMessageCodec.decode(payload));
    }

    @Test
    public void ackUsesSameEnvelopeAndCarriesNoImplicitAttachment() throws Exception {
        PeerAppMessageCodec.PeerAppMessage ack = new PeerAppMessageCodec.PeerAppMessage();
        ack.type = PeerAppMessageCodec.TYPE_ACK;
        ack.id = "msg-1";
        ack.fromClientId = 2L;
        ack.toClientId = 1L;
        ack.attachment = new JSONObject().put("objectId", "must-not-leak");

        byte[] payload = PeerAppMessageCodec.encode(ack);
        assertEquals("STMSG2\n", new String(payload, 0, 7, StandardCharsets.US_ASCII));
        PeerAppMessageCodec.PeerAppMessage decoded =
                PeerAppMessageCodec.decode(payload);
        assertNotNull(decoded);
        assertEquals(PeerAppMessageCodec.TYPE_ACK, decoded.type);
        assertEquals("msg-1", decoded.id);
        assertNull(decoded.attachment);
    }

    @Test
    public void invalidOrUnrelatedPayloadIsNotAcceptedAsAppMessage() {
        assertFalse(PeerAppMessageCodec.looksLike("hello".getBytes(StandardCharsets.UTF_8)));
        assertNull(PeerAppMessageCodec.decode("STMSG2\n{".getBytes(StandardCharsets.UTF_8)));
        assertNull(PeerAppMessageCodec.decode(
                "STMSG2\n{}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void attachmentDisplayFallsBackForBlankMetadata() throws Exception {
        PeerAppMessageCodec.PeerAppMessage message = new PeerAppMessageCodec.PeerAppMessage();
        message.message = "";
        message.attachment = new JSONObject()
                .put("fileName", " ")
                .put("objectId", "obj-2")
                .put("mimeType", "")
                .put("sizeBytes", 0L);
        assertEquals("[附件] obj-2 · application/octet-stream · -",
                PeerAppMessageCodec.displayText(message));
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
