package com.theshuai.tunnelserver.websocket;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

final class PublicTransferRelayFrame {
    static final int MAX_WIRE_BYTES = 64 * 1024;
    static final int APP_TYPE_ACK = 127;

    private static final int RELAY_MAGIC = 0x53545752; // STWR
    private static final int APP_MAGIC = 0x53544150; // STAP
    private static final int VERSION = 2;
    private static final int RELAY_HEADER_BYTES = 14;
    private static final int APP_HEADER_BYTES = 72;
    private static final int MAX_PEER_ID_BYTES = 512;
    private static final int MAX_APP_MESSAGE_BYTES = 8 * 1024 * 1024;
    private static final int MAX_CHUNK_COUNT = 2048;
    private static final int APP_FLAG_ACK_REQUIRED = 1;

    private PublicTransferRelayFrame() {
    }

    static ClientFrame decodeClient(ByteBuffer source) {
        ByteBuffer buffer = source.asReadOnlyBuffer();
        int wireBytes = buffer.remaining();
        if (wireBytes < RELAY_HEADER_BYTES + APP_HEADER_BYTES || wireBytes > MAX_WIRE_BYTES) {
            throw invalid("relay frame length");
        }
        if (buffer.getInt() != RELAY_MAGIC || Byte.toUnsignedInt(buffer.get()) != VERSION) {
            throw invalid("relay frame version");
        }
        if (Byte.toUnsignedInt(buffer.get()) != 0) {
            throw invalid("relay frame flags");
        }
        int targetLength = Short.toUnsignedInt(buffer.getShort());
        int sourceLength = Short.toUnsignedInt(buffer.getShort());
        int payloadLength = buffer.getInt();
        if (targetLength < 1 || targetLength > MAX_PEER_ID_BYTES || sourceLength != 0
                || payloadLength < APP_HEADER_BYTES
                || RELAY_HEADER_BYTES + targetLength + payloadLength != wireBytes) {
            throw invalid("relay frame fields");
        }
        byte[] targetBytes = new byte[targetLength];
        buffer.get(targetBytes);
        String targetPeerId = strictUtf8(targetBytes);
        if (targetPeerId.isBlank() || targetPeerId.codePoints().anyMatch(Character::isISOControl)) {
            throw invalid("target peer id");
        }
        byte[] appFrame = new byte[payloadLength];
        buffer.get(appFrame);
        int appType = validateAppFrame(ByteBuffer.wrap(appFrame));
        if (buffer.hasRemaining()) {
            throw invalid("relay frame trailing bytes");
        }
        return new ClientFrame(targetPeerId, appType, appFrame);
    }

    static byte[] encodeServer(String targetPeerId, String sourcePeerId, byte[] appFrame) {
        byte[] target = targetPeerId.getBytes(StandardCharsets.UTF_8);
        byte[] source = sourcePeerId.getBytes(StandardCharsets.UTF_8);
        if (target.length < 1 || target.length > MAX_PEER_ID_BYTES
                || source.length < 1 || source.length > MAX_PEER_ID_BYTES) {
            throw invalid("peer id length");
        }
        validateAppFrame(ByteBuffer.wrap(appFrame));
        int wireBytes = RELAY_HEADER_BYTES + target.length + source.length + appFrame.length;
        if (wireBytes > MAX_WIRE_BYTES) {
            throw invalid("relay frame length");
        }
        ByteBuffer result = ByteBuffer.allocate(wireBytes);
        result.putInt(RELAY_MAGIC);
        result.put((byte) VERSION);
        result.put((byte) 0);
        result.putShort((short) target.length);
        result.putShort((short) source.length);
        result.putInt(appFrame.length);
        result.put(target);
        result.put(source);
        result.put(appFrame);
        return result.array();
    }

    private static int validateAppFrame(ByteBuffer buffer) {
        int wireBytes = buffer.remaining();
        if (wireBytes < APP_HEADER_BYTES || buffer.getInt() != APP_MAGIC
                || Byte.toUnsignedInt(buffer.get()) != VERSION) {
            throw invalid("app frame version");
        }
        int type = Byte.toUnsignedInt(buffer.get());
        if (type != 1 && type != 2 && type != 3 && type != APP_TYPE_ACK) {
            throw invalid("app frame type");
        }
        int flags = Short.toUnsignedInt(buffer.getShort());
        if ((flags & ~APP_FLAG_ACK_REQUIRED) != 0 || (type == APP_TYPE_ACK && flags != 0)) {
            throw invalid("app frame flags");
        }
        buffer.position(buffer.position() + 16);
        long chunkIndex = Integer.toUnsignedLong(buffer.getInt());
        long chunkCount = Integer.toUnsignedLong(buffer.getInt());
        long totalLength = Integer.toUnsignedLong(buffer.getInt());
        long payloadLength = Integer.toUnsignedLong(buffer.getInt());
        buffer.position(buffer.position() + 32);
        if (chunkCount < 1 || chunkCount > MAX_CHUNK_COUNT || chunkIndex >= chunkCount
                || totalLength > MAX_APP_MESSAGE_BYTES || payloadLength > totalLength
                || payloadLength != buffer.remaining()
                || APP_HEADER_BYTES + payloadLength != wireBytes) {
            throw invalid("app frame fields");
        }
        return type;
    }

    private static String strictUtf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw invalid("invalid UTF-8");
        }
    }

    private static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException("invalid " + reason);
    }

    record ClientFrame(String targetPeerId, int appType, byte[] appFrame) {
    }
}
