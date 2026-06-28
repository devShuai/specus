package com.theshuai.common.peermesh;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public record PeerRelayBinaryFrame(
        byte type,
        String fromAllocationId,
        String toAllocationId,
        byte[] payload
) {
    public static final byte TYPE_SEND = 1;
    public static final byte TYPE_DATA = 2;
    private static final int MAGIC = 0x53505231; // SPR1
    private static final byte VERSION = 1;
    private static final int FIXED_HEADER_BYTES = Integer.BYTES + 2 + Short.BYTES * 2 + Integer.BYTES;
    private static final int MAX_ALLOCATION_ID_BYTES = 128;

    public static PeerRelayBinaryFrame send(String fromAllocationId, String toAllocationId, byte[] payload) {
        return new PeerRelayBinaryFrame(TYPE_SEND, fromAllocationId, toAllocationId, payload);
    }

    public static PeerRelayBinaryFrame data(String fromAllocationId, String toAllocationId, byte[] payload) {
        return new PeerRelayBinaryFrame(TYPE_DATA, fromAllocationId, toAllocationId, payload);
    }

    public static PeerRelayBinaryFrame parse(byte[] packet) {
        if (packet == null) {
            return null;
        }
        return parse(packet, 0, packet.length);
    }

    public static PeerRelayBinaryFrame parse(byte[] packet, int offset, int length) {
        if (packet == null || offset < 0 || length < FIXED_HEADER_BYTES || offset + length > packet.length) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.wrap(packet, offset, length);
        int magic = buffer.getInt();
        byte version = buffer.get();
        byte type = buffer.get();
        if (magic != MAGIC || version != VERSION || (type != TYPE_SEND && type != TYPE_DATA)) {
            return null;
        }
        int fromLength = Short.toUnsignedInt(buffer.getShort());
        int toLength = Short.toUnsignedInt(buffer.getShort());
        int payloadLength = buffer.getInt();
        if (fromLength <= 0 || fromLength > MAX_ALLOCATION_ID_BYTES
                || toLength <= 0 || toLength > MAX_ALLOCATION_ID_BYTES
                || payloadLength < 0
                || buffer.remaining() != fromLength + toLength + payloadLength) {
            return null;
        }
        byte[] fromBytes = new byte[fromLength];
        byte[] toBytes = new byte[toLength];
        byte[] payload = new byte[payloadLength];
        buffer.get(fromBytes);
        buffer.get(toBytes);
        buffer.get(payload);
        return new PeerRelayBinaryFrame(
                type,
                new String(fromBytes, StandardCharsets.UTF_8),
                new String(toBytes, StandardCharsets.UTF_8),
                payload
        );
    }

    public byte[] toBytes() {
        byte[] fromBytes = allocationBytes(fromAllocationId);
        byte[] toBytes = allocationBytes(toAllocationId);
        byte[] payloadBytes = payload == null ? new byte[0] : Arrays.copyOf(payload, payload.length);
        ByteBuffer buffer = ByteBuffer.allocate(FIXED_HEADER_BYTES + fromBytes.length + toBytes.length + payloadBytes.length);
        buffer.putInt(MAGIC);
        buffer.put(VERSION);
        buffer.put(type);
        buffer.putShort((short) fromBytes.length);
        buffer.putShort((short) toBytes.length);
        buffer.putInt(payloadBytes.length);
        buffer.put(fromBytes);
        buffer.put(toBytes);
        buffer.put(payloadBytes);
        return buffer.array();
    }

    private static byte[] allocationBytes(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("allocation id is required");
        }
        byte[] bytes = value.trim().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_ALLOCATION_ID_BYTES) {
            throw new IllegalArgumentException("allocation id is too long");
        }
        return bytes;
    }
}
