package com.theshuai.specusserver.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Bounds on how much a compressed body may expand.
 *
 * <p>Decompression is the one place where a small input costs unbounded memory. A few kilobytes of
 * crafted gzip expands to gigabytes, so reading a decompressor to EOF hands any upstream — or any
 * peer able to influence one — a way to end the process.
 *
 * <p>Two limits, because either alone leaves a gap. The absolute cap bounds what a single body can
 * cost. The ratio cap catches a bomb that stays under the absolute cap but is still wildly
 * disproportionate to its input, which is the signature of a bomb rather than of real content.
 */
public final class DecompressionLimits {
    /** Matches the largest body the proxy carries anyway, so no legitimate payload is lost to it. */
    public static final int MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;
    /** Generous next to real text, which rarely exceeds 20:1. */
    public static final int MAX_RATIO = 100;
    /** Keeps the ratio from rejecting tiny inputs, where framing overhead dominates. */
    public static final int MIN_RATIO_ALLOWANCE_BYTES = 64 * 1024;

    private DecompressionLimits() {
    }

    /** Thrown when a body exceeds either limit. */
    public static final class LimitExceededException extends IOException {
        LimitExceededException(long produced, int compressedSize) {
            super("decompressed body exceeded its limit: " + produced
                    + " bytes from " + compressedSize + " compressed");
        }
    }

    /** Returns the smaller of the absolute cap and the ratio allowance. */
    public static int limitFor(int compressedSize) {
        if (compressedSize <= 0) {
            return MIN_RATIO_ALLOWANCE_BYTES;
        }
        long scaled = (long) compressedSize * MAX_RATIO;
        long allowance = Math.max(MIN_RATIO_ALLOWANCE_BYTES, scaled);
        return (int) Math.min(allowance, MAX_DECOMPRESSED_BYTES);
    }

    /**
     * Reads the decompressor, refusing anything past the byte or ratio cap.
     *
     * @param compressedSize size of the input handed to the decompressor, which is what makes the
     *                       ratio check possible
     */
    public static byte[] readAllBounded(InputStream input, int compressedSize) throws IOException {
        int limit = limitFor(compressedSize);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long produced = 0;
        int read;
        while ((read = input.read(buffer)) >= 0) {
            produced += read;
            if (produced > limit) {
                throw new LimitExceededException(produced, compressedSize);
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }
}
