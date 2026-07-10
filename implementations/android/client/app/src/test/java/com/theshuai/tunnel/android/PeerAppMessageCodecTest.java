package com.theshuai.tunnel.android;

import org.json.JSONObject;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class PeerAppMessageCodecTest {
    @Test
    public void ordinaryTextUsesJavaAndGoStmsg1WireFormat() throws Exception {
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

        assertEquals("STMSG1\n", new String(payload, 0, 7, StandardCharsets.US_ASCII));
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
    public void javaAndGoStmsg1PayloadRemainsReadable() throws Exception {
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

        assertTrue(PeerAppMessageCodec.looksLike(payload));
        PeerAppMessageCodec.PeerAppMessage decoded = PeerAppMessageCodec.decode(payload);
        assertNotNull(decoded);
        assertEquals("old", decoded.id);
        assertEquals(7L, decoded.fromClientId);
        assertEquals("java-or-go", decoded.fromClientName);
        assertEquals(8L, decoded.toClientId);
        assertEquals("android", decoded.toClientName);
        assertEquals("legacy", decoded.message);
        assertEquals(4567L, decoded.createdAtMillis);
        assertNull(decoded.attachment);
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
        assertEquals("STMSG1\n", new String(payload, 0, 7, StandardCharsets.US_ASCII));
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
}
