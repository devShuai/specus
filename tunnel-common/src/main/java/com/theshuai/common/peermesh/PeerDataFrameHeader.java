package com.theshuai.common.peermesh;

import java.nio.ByteBuffer;

public record PeerDataFrameHeader(
        long sessionId,
        long fromClientId,
        long toClientId,
        long sequence
) {
    private static final int MAGIC = 0x53504D31; // SPM1
    private static final byte VERSION = 1;
    private static final byte TYPE_DATA = 1;
    private static final int NONCE_BYTES = 12;
    private static final int HEADER_BYTES = Integer.BYTES + 2 + Long.BYTES * 4 + NONCE_BYTES;

    public static PeerDataFrameHeader parse(byte[] packet) {
        if (packet == null || packet.length < HEADER_BYTES + Integer.BYTES) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        int magic = buffer.getInt();
        byte version = buffer.get();
        byte type = buffer.get();
        if (magic != MAGIC || version != VERSION || type != TYPE_DATA) {
            return null;
        }
        long sessionId = buffer.getLong();
        long fromClientId = buffer.getLong();
        long toClientId = buffer.getLong();
        long sequence = buffer.getLong();
        return new PeerDataFrameHeader(sessionId, fromClientId, toClientId, sequence);
    }
}
