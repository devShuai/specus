package com.theshuai.common.peermesh;

import java.nio.ByteBuffer;

public record PeerDataFrameHeader(
        long sessionId,
        long sequence
) {
    private static final int MAGIC = 0x53504D32; // SPM2
    private static final int TAG_BYTES = 16;
    private static final int HEADER_BYTES = Integer.BYTES + Long.BYTES * 2;
    private static final int MIN_BYTES = HEADER_BYTES + TAG_BYTES;
    private static final int MAX_BYTES = 65_535;

    public static boolean looksLikeDataFrame(byte[] packet) {
        return packet != null
                && packet.length >= Integer.BYTES
                && ByteBuffer.wrap(packet, 0, Integer.BYTES).getInt() == MAGIC;
    }

    public static PeerDataFrameHeader parse(byte[] packet) {
        if (packet == null || packet.length < MIN_BYTES || packet.length > MAX_BYTES) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        if (buffer.getInt() != MAGIC) {
            return null;
        }
        long sessionId = buffer.getLong();
        long sequence = buffer.getLong();
        return sessionId > 0 && sequence > 0
                ? new PeerDataFrameHeader(sessionId, sequence)
                : null;
    }
}
