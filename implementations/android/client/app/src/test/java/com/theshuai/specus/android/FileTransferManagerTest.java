package com.theshuai.specus.android;

import org.json.JSONObject;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class FileTransferManagerTest {
    @Test
    public void offerRoundTripsWithAllMetadata() throws Exception {
        String body = FileTransferManager.buildOffer("abc123", "报告 最终版.pdf", 123456L, "application/pdf", 206);

        assertTrue(FileTransferManager.isTransferMessage(body));
        JSONObject parsed = FileTransferManager.parseTransfer(body);
        assertNotNull(parsed);
        assertEquals("offer", parsed.getString("t"));
        assertEquals("abc123", parsed.getString("id"));
        assertEquals("报告 最终版.pdf", parsed.getString("name"));
        assertEquals(123456L, parsed.getLong("size"));
        assertEquals("application/pdf", parsed.getString("mime"));
        assertEquals(206, parsed.getInt("chunks"));
    }

    @Test
    public void chunkCarriesBase64Payload() throws Exception {
        byte[] data = new byte[600];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 31);
        }

        String body = FileTransferManager.buildChunk("id-1", 7, data, 300);

        JSONObject parsed = FileTransferManager.parseTransfer(body);
        assertNotNull(parsed);
        assertEquals("chunk", parsed.getString("t"));
        assertEquals("id-1", parsed.getString("id"));
        assertEquals(7, parsed.getInt("seq"));
        byte[] decoded = Base64.getDecoder().decode(parsed.getString("data"));
        assertEquals(300, decoded.length);
        byte[] expected = new byte[300];
        System.arraycopy(data, 0, expected, 0, 300);
        assertArrayEquals(expected, decoded);
    }

    @Test
    public void chunkFitsPeerMeshUdpBudget() throws Exception {
        byte[] data = new byte[600];
        String body = FileTransferManager.buildChunk("id-1", 0, data, data.length);

        assertTrue(body.getBytes(StandardCharsets.UTF_8).length <= 1100);
    }

    @Test
    public void doneAndAbortRoundTrip() throws Exception {
        JSONObject done = FileTransferManager.parseTransfer(FileTransferManager.buildDone("id-9"));
        assertNotNull(done);
        assertEquals("done", done.getString("t"));
        assertEquals("id-9", done.getString("id"));

        JSONObject abort = FileTransferManager.parseTransfer(FileTransferManager.buildAbort("id-9", "disk full"));
        assertNotNull(abort);
        assertEquals("abort", abort.getString("t"));
        assertEquals("disk full", abort.getString("reason"));
    }

    @Test
    public void plainTextIsNotTransferMessage() {
        assertFalse(FileTransferManager.isTransferMessage("hello world"));
        assertFalse(FileTransferManager.isTransferMessage(null));
        assertFalse(FileTransferManager.isTransferMessage("STXFER2\n{}"));
        assertNull(FileTransferManager.parseTransfer("hello world"));
    }

    @Test
    public void malformedTransferPayloadReturnsNull() {
        assertTrue(FileTransferManager.isTransferMessage("STXFER1\nnot-json"));
        assertNull(FileTransferManager.parseTransfer("STXFER1\nnot-json"));
    }

    @Test
    public void formatBytesMatchesUiStyle() {
        assertEquals("0 B", FileTransferManager.formatBytes(0));
        assertEquals("512 B", FileTransferManager.formatBytes(512));
        assertEquals("1.0 KB", FileTransferManager.formatBytes(1024));
        assertEquals("10 MB", FileTransferManager.formatBytes(10 * 1024 * 1024));
    }
}
