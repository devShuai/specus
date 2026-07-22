package com.theshuai.tunnelserver.websocket;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Internal Redis Pub/Sub envelope. Browser-facing STWR2/STAP2 bytes remain unchanged. */
final class PublicTransferClusterFrame {
    static final byte KIND_ROSTER = 1;
    static final byte KIND_TEXT = 2;
    static final byte KIND_BINARY = 3;
    static final byte KIND_MANAGEMENT = 4;
    static final byte FLAG_EXCLUDE_SOURCE = 1;
    private static final byte[] MAGIC = {'S', 'T', 'C', 'E'};
    private static final byte VERSION = 2;
    private static final int HEADER_BYTES = 26;
    private static final int MAX_GROUP_BYTES = 128;
    private static final int MAX_ID_BYTES = 512;
    private static final int MAX_PAYLOAD_BYTES = 256 * 1024;

    private PublicTransferClusterFrame() {
    }

    static byte[] encode(Event event) {
        byte[] group = utf8(event.groupId());
        byte[] target = utf8(event.targetPeerId());
        byte[] sourceLease = utf8(event.sourceLeaseId());
        byte[] payload = event.payload() == null ? new byte[0] : event.payload();
        validateKind(event.kind());
        validateLength("group", group.length, MAX_GROUP_BYTES);
        validateLength("target", target.length, MAX_ID_BYTES);
        validateLength("source lease", sourceLease.length, MAX_ID_BYTES);
        validateLength("payload", payload.length, MAX_PAYLOAD_BYTES);
        if (group.length == 0) {
            throw new IllegalArgumentException("cluster event group is required");
        }
        if (event.kind() == KIND_ROSTER && payload.length != 0) {
            throw new IllegalArgumentException("roster event payload must be empty");
        }
        if (event.kind() == KIND_BINARY && target.length == 0) {
            throw new IllegalArgumentException("binary event target is required");
        }
        if (event.kind() == KIND_MANAGEMENT && (payload.length == 0 || target.length != 0
                || sourceLease.length != 0 || event.revision() != 0 || event.excludeSource())) {
            throw new IllegalArgumentException("management event shape is invalid");
        }
        ByteBuffer result = ByteBuffer.allocate(
                        HEADER_BYTES + group.length + target.length + sourceLease.length + payload.length)
                .order(ByteOrder.BIG_ENDIAN);
        result.put(MAGIC);
        result.put(VERSION);
        result.put(event.kind());
        result.put(event.excludeSource() ? FLAG_EXCLUDE_SOURCE : (byte) 0);
        result.put((byte) 0);
        result.putLong(event.revision());
        result.putShort((short) group.length);
        result.putShort((short) target.length);
        result.putShort((short) sourceLease.length);
        result.putInt(payload.length);
        result.put(group).put(target).put(sourceLease).put(payload);
        return result.array();
    }

    static Event decode(byte[] encoded) {
        if (encoded == null || encoded.length < HEADER_BYTES) {
            throw new IllegalArgumentException("cluster event is truncated");
        }
        ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[4];
        input.get(magic);
        if (!Arrays.equals(magic, MAGIC) || input.get() != VERSION) {
            throw new IllegalArgumentException("unsupported cluster event");
        }
        byte kind = input.get();
        validateKind(kind);
        byte flags = input.get();
        if ((flags & ~FLAG_EXCLUDE_SOURCE) != 0 || input.get() != 0) {
            throw new IllegalArgumentException("invalid cluster event flags");
        }
        long revision = input.getLong();
        int groupLength = Short.toUnsignedInt(input.getShort());
        int targetLength = Short.toUnsignedInt(input.getShort());
        int sourceLeaseLength = Short.toUnsignedInt(input.getShort());
        int payloadLength = input.getInt();
        validateLength("group", groupLength, MAX_GROUP_BYTES);
        validateLength("target", targetLength, MAX_ID_BYTES);
        validateLength("source lease", sourceLeaseLength, MAX_ID_BYTES);
        validateLength("payload", payloadLength, MAX_PAYLOAD_BYTES);
        long expectedLength = (long) HEADER_BYTES + groupLength + targetLength
                + sourceLeaseLength + payloadLength;
        if (expectedLength != encoded.length) {
            throw new IllegalArgumentException("cluster event length mismatch");
        }
        String groupId = readUtf8(input, groupLength);
        String targetPeerId = readUtf8(input, targetLength);
        String sourceLeaseId = readUtf8(input, sourceLeaseLength);
        byte[] payload = new byte[payloadLength];
        input.get(payload);
        if (groupId.isBlank()) {
            throw new IllegalArgumentException("cluster event group is required");
        }
        if (kind == KIND_ROSTER && payloadLength != 0) {
            throw new IllegalArgumentException("roster event payload must be empty");
        }
        if (kind == KIND_BINARY && targetPeerId.isBlank()) {
            throw new IllegalArgumentException("binary event target is required");
        }
        if (kind == KIND_MANAGEMENT && (payloadLength == 0 || !targetPeerId.isEmpty()
                || !sourceLeaseId.isEmpty() || revision != 0 || (flags & FLAG_EXCLUDE_SOURCE) != 0)) {
            throw new IllegalArgumentException("management event shape is invalid");
        }
        return new Event(kind, (flags & FLAG_EXCLUDE_SOURCE) != 0, revision,
                groupId, targetPeerId, sourceLeaseId, payload);
    }

    private static byte[] utf8(String value) {
        return value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
    }

    private static String readUtf8(ByteBuffer input, int length) {
        ByteBuffer value = input.slice(input.position(), length);
        input.position(input.position() + length);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(value)
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("cluster event contains invalid UTF-8", exception);
        }
    }

    private static void validateKind(byte kind) {
        if (kind != KIND_ROSTER && kind != KIND_TEXT && kind != KIND_BINARY
                && kind != KIND_MANAGEMENT) {
            throw new IllegalArgumentException("unsupported cluster event kind");
        }
    }

    private static void validateLength(String field, int length, int maximum) {
        if (length < 0 || length > maximum) {
            throw new IllegalArgumentException(field + " length is invalid");
        }
    }

    record Event(
            byte kind,
            boolean excludeSource,
            long revision,
            String groupId,
            String targetPeerId,
            String sourceLeaseId,
            byte[] payload) {
    }
}
