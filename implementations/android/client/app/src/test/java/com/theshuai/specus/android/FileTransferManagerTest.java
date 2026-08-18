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

    @Test
    public void offerCarriesWholeFileDigestWhenAvailable() throws Exception {
        String body = FileTransferManager.buildOffer("id-d", "a.bin", 3L, "application/octet-stream", 1,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        JSONObject parsed = FileTransferManager.parseTransfer(body);
        assertNotNull(parsed);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                parsed.getString("sha256"));

        // Peers that predate the digest simply omit the field.
        JSONObject legacy = FileTransferManager.parseTransfer(
                FileTransferManager.buildOffer("id-l", "a.bin", 3L, "application/octet-stream", 1));
        assertNotNull(legacy);
        assertFalse(legacy.has("sha256"));
    }

    @Test
    public void sanitizeNameReducesPeerInputToABareFileName() {
        assertEquals("escape.txt", FileTransferManager.sanitizeName("../../escape.txt"));
        assertEquals("escape.txt", FileTransferManager.sanitizeName("..\\..\\escape.txt"));
        assertEquals("passwd", FileTransferManager.sanitizeName("/etc/passwd"));
        assertEquals("evil.so", FileTransferManager.sanitizeName("/data/data/other.app/files/evil.so"));
        assertEquals("file", FileTransferManager.sanitizeName(".."));
        assertEquals("file", FileTransferManager.sanitizeName("   "));
        assertEquals("file", FileTransferManager.sanitizeName(null));
        // Characters that would confuse the filesystem are replaced rather than kept.
        assertEquals("a_b.txt", FileTransferManager.sanitizeName("a:b.txt"));
    }

    @Test
    public void fileDigestMatchesKnownSha256() throws Exception {
        java.io.File file = java.io.File.createTempFile("specus-digest", ".bin");
        file.deleteOnExit();
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(file)) {
            out.write("abc".getBytes(StandardCharsets.UTF_8));
        }

        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                FileTransferManager.fileDigest(file));
    }

    @Test
    public void zeroByteOfferCarriesNoChunks() throws Exception {
        JSONObject parsed = FileTransferManager.parseTransfer(
                FileTransferManager.buildOffer("id-0", "empty.txt", 0L, "text/plain", 0));

        assertNotNull(parsed);
        assertEquals(0L, parsed.getLong("size"));
        assertEquals(0, parsed.getInt("chunks"));
    }
}
