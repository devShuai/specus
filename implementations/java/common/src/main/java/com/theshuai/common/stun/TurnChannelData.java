package com.theshuai.common.stun;

import java.nio.ByteBuffer;
import java.util.Arrays;

public final class TurnChannelData {
    public static final int MIN_CHANNEL = 0x4000;
    public static final int MAX_CHANNEL = 0x7FFF;
    public static final int HEADER_BYTES = 4;
    public static final int MAX_PAYLOAD_BYTES = 65_535;

    private TurnChannelData() {
    }

    public static boolean looksLike(byte[] packet, int offset, int length) {
        if (packet == null || offset < 0 || length < HEADER_BYTES || offset > packet.length - length) {
            return false;
        }
        int channel = Short.toUnsignedInt(ByteBuffer.wrap(packet, offset, Short.BYTES).getShort());
        return channel >= MIN_CHANNEL && channel <= MAX_CHANNEL;
    }

    public static Frame parse(byte[] packet, int offset, int length) {
        if (!looksLike(packet, offset, length)) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.wrap(packet, offset, length);
        int channel = Short.toUnsignedInt(buffer.getShort());
        int payloadLength = Short.toUnsignedInt(buffer.getShort());
        int trailing = buffer.remaining() - payloadLength;
        if (payloadLength > buffer.remaining() || trailing < 0 || trailing > 3) {
            return null;
        }
        byte[] payload = new byte[payloadLength];
        buffer.get(payload);
        while (buffer.hasRemaining()) {
            if (buffer.get() != 0) {
                return null;
            }
        }
        return new Frame(channel, payload);
    }

    public static byte[] encode(int channelNumber, byte[] payload) {
        if (channelNumber < MIN_CHANNEL || channelNumber > MAX_CHANNEL) {
            throw new IllegalArgumentException("TURN channel number must be between 0x4000 and 0x7FFF");
        }
        byte[] body = payload == null ? new byte[0] : payload;
        if (body.length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("TURN ChannelData payload exceeds 65535 bytes");
        }
        ByteBuffer frame = ByteBuffer.allocate(HEADER_BYTES + body.length);
        frame.putShort((short) channelNumber);
        frame.putShort((short) body.length);
        frame.put(body);
        return frame.array();
    }

    public record Frame(int channelNumber, byte[] payload) {
        public Frame {
            payload = payload == null ? new byte[0] : Arrays.copyOf(payload, payload.length);
        }

        @Override
        public byte[] payload() {
            return Arrays.copyOf(payload, payload.length);
        }
    }
}
