package com.theshuai.specusserver.http;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DecompressionLimitsTests {
    @Test
    void ordinaryBodiesDecompressUnchanged() throws Exception {
        byte[] payload = "the quick brown fox. ".repeat(2000).getBytes();
        byte[] compressed = gzip(payload);

        try (GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
            assertArrayEquals(payload,
                    DecompressionLimits.readAllBounded(input, compressed.length));
        }
    }

    /** A few kilobytes of crafted gzip expands to gigabytes. Reading to EOF would end the process. */
    @Test
    void decompressionBombIsRefused() throws Exception {
        byte[] bomb = gzip(new byte[32 * 1024 * 1024]);

        try (GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(bomb))) {
            assertThrows(DecompressionLimits.LimitExceededException.class,
                    () -> DecompressionLimits.readAllBounded(input, bomb.length));
        }
    }

    @Test
    void limitCombinesTheAbsoluteAndRatioCaps() {
        // Tiny inputs get the flat allowance, so framing overhead cannot make the ratio meaningless.
        assertEquals(DecompressionLimits.MIN_RATIO_ALLOWANCE_BYTES, DecompressionLimits.limitFor(0));
        assertEquals(DecompressionLimits.MIN_RATIO_ALLOWANCE_BYTES, DecompressionLimits.limitFor(-1));

        // In the middle the ratio binds.
        assertEquals(256 * 1024 * DecompressionLimits.MAX_RATIO,
                DecompressionLimits.limitFor(256 * 1024));

        // Past that the absolute cap binds, including for a size large enough to overflow a naive
        // multiplication.
        assertEquals(DecompressionLimits.MAX_DECOMPRESSED_BYTES,
                DecompressionLimits.limitFor(1024 * 1024));
        assertEquals(DecompressionLimits.MAX_DECOMPRESSED_BYTES,
                DecompressionLimits.limitFor(Integer.MAX_VALUE));
    }

    /** A body that exactly fills its allowance is legitimate and must not be rejected. */
    @Test
    void bodyWithinTheAllowanceIsAccepted() throws Exception {
        byte[] payload = new byte[DecompressionLimits.MIN_RATIO_ALLOWANCE_BYTES];
        java.util.Arrays.fill(payload, (byte) 'x');
        byte[] compressed = gzip(payload);

        try (GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
            assertEquals(payload.length,
                    DecompressionLimits.readAllBounded(input, compressed.length).length);
        }
    }

    private static byte[] gzip(byte[] payload) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (GZIPOutputStream compressor = new GZIPOutputStream(buffer)) {
            compressor.write(payload);
        }
        return buffer.toByteArray();
    }
}
