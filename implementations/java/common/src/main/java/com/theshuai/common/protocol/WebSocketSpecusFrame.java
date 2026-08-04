package com.theshuai.common.protocol;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Explicit WebSocket frame envelope carried inside NAT stream v2 DATA. */
public record WebSocketSpecusFrame(int opcode, boolean finalFragment, int rsv,
                                   int closeCode, byte[] payload) {
    public static final int MAGIC = 0x53575332; // SWS2
    public static final int HEADER_BYTES = 12;
    public static final int MAX_PAYLOAD_BYTES = 64 * 1024 - HEADER_BYTES;

    public static final int OPCODE_CONTINUATION = 0x0;
    public static final int OPCODE_TEXT = 0x1;
    public static final int OPCODE_BINARY = 0x2;
    public static final int OPCODE_CLOSE = 0x8;
    public static final int OPCODE_PING = 0x9;
    public static final int OPCODE_PONG = 0xA;

    public WebSocketSpecusFrame {
        payload = payload == null ? new byte[0] : payload;
        validate(opcode, finalFragment, rsv, closeCode, payload.length);
        payload = payload.clone();
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    public byte[] encode() {
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_BYTES + payload.length).order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(MAGIC);
        buffer.put((byte) opcode);
        int flags = (finalFragment ? 0x01 : 0) | ((rsv & 0x07) << 1);
        buffer.put((byte) flags);
        buffer.putShort((short) closeCode);
        buffer.putInt(payload.length);
        buffer.put(payload);
        return buffer.array();
    }

    public static WebSocketSpecusFrame decode(byte[] encoded) {
        if (encoded == null || encoded.length < HEADER_BYTES) {
            throw new IllegalArgumentException("truncated SWS2 frame");
        }
        ByteBuffer buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        if (buffer.getInt() != MAGIC) {
            throw new IllegalArgumentException("invalid SWS2 magic");
        }
        int opcode = Byte.toUnsignedInt(buffer.get());
        int flags = Byte.toUnsignedInt(buffer.get());
        if ((flags & 0xF0) != 0) {
            throw new IllegalArgumentException("unknown SWS2 flags");
        }
        boolean finalFragment = (flags & 0x01) != 0;
        int rsv = (flags >>> 1) & 0x07;
        int closeCode = Short.toUnsignedInt(buffer.getShort());
        int payloadLength = buffer.getInt();
        if (payloadLength < 0 || payloadLength > MAX_PAYLOAD_BYTES
                || buffer.remaining() != payloadLength) {
            throw new IllegalArgumentException("invalid SWS2 payload length");
        }
        byte[] payload = new byte[payloadLength];
        buffer.get(payload);
        return new WebSocketSpecusFrame(opcode, finalFragment, rsv, closeCode, payload);
    }

    private static void validate(int opcode, boolean finalFragment, int rsv, int closeCode, int payloadLength) {
        if (opcode != OPCODE_CONTINUATION && opcode != OPCODE_TEXT && opcode != OPCODE_BINARY
                && opcode != OPCODE_CLOSE && opcode != OPCODE_PING && opcode != OPCODE_PONG) {
            throw new IllegalArgumentException("unsupported SWS2 opcode: " + opcode);
        }
        if (rsv < 0 || rsv > 7) {
            throw new IllegalArgumentException("invalid SWS2 RSV bits");
        }
        if (payloadLength < 0 || payloadLength > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("SWS2 payload exceeds frame limit");
        }
        boolean control = opcode >= OPCODE_CLOSE;
        if (control && (!finalFragment || payloadLength > 125 || rsv != 0)) {
            throw new IllegalArgumentException("invalid fragmented/control SWS2 frame");
        }
        if (opcode == OPCODE_CLOSE) {
            if (payloadLength > 123) {
                throw new IllegalArgumentException("WebSocket close reason exceeds 123 bytes");
            }
            if (closeCode != 0 && (closeCode < 1000 || closeCode >= 5000
                    || isWireForbiddenCloseCode(closeCode))) {
                throw new IllegalArgumentException("invalid WebSocket close code");
            }
            if (closeCode == 0 && payloadLength != 0) {
                throw new IllegalArgumentException("WebSocket close reason requires a close code");
            }
        } else if (closeCode != 0) {
            throw new IllegalArgumentException("close code is only valid on CLOSE");
        }
    }

    private static boolean isWireForbiddenCloseCode(int closeCode) {
        return closeCode == 1004 || closeCode == 1005 || closeCode == 1006 || closeCode == 1015;
    }
}
