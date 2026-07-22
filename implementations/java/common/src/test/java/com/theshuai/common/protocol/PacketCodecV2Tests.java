package com.theshuai.common.protocol;

import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.serialize.SerializerAlgorithm;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PacketCodecV2Tests {
    @Test
    void shouldRejectV1Frame() {
        ByteBuf frame = frame(1, SerializerAlgorithm.BIN, Command.HEARTBEAT_REQUEST, new byte[0]);
        try {
            ProtocolException exception = assertThrows(ProtocolException.class, () -> PacketCodec.INSTANCE.decode(frame));
            assertEquals(ProtocolException.Reason.UNSUPPORTED_VERSION, exception.getReason());
        } finally {
            frame.release();
        }
    }

    @Test
    void shouldRejectNonCompactSerializer() {
        ByteBuf frame = frame(PacketCodec.PROTOCOL_VERSION, (byte) 1, Command.HEARTBEAT_REQUEST, new byte[0]);
        try {
            ProtocolException exception = assertThrows(ProtocolException.class, () -> PacketCodec.INSTANCE.decode(frame));
            assertEquals(ProtocolException.Reason.UNSUPPORTED_SERIALIZER, exception.getReason());
        } finally {
            frame.release();
        }
    }

    @Test
    void shouldRejectUnknownCommand() {
        ByteBuf frame = frame(PacketCodec.PROTOCOL_VERSION, SerializerAlgorithm.BIN, (byte) 127, new byte[0]);
        try {
            ProtocolException exception = assertThrows(ProtocolException.class, () -> PacketCodec.INSTANCE.decode(frame));
            assertEquals(ProtocolException.Reason.UNKNOWN_COMMAND, exception.getReason());
        } finally {
            frame.release();
        }
    }

    @Test
    void shouldRejectTrailingBytes() throws Exception {
        ByteBuf encoded = Unpooled.buffer();
        try {
            PacketCodec.INSTANCE.encode(encoded, new HeartBeatRequestPacket());
            encoded.writeByte(1);
            ProtocolException exception = assertThrows(ProtocolException.class, () -> PacketCodec.INSTANCE.decode(encoded));
            assertEquals(ProtocolException.Reason.INVALID_LENGTH, exception.getReason());
        } finally {
            encoded.release();
        }
    }

    @Test
    void shouldRejectOversizedLoginBeforeEncoding() {
        LoginRequestPacket packet = new LoginRequestPacket();
        packet.setClientName("client");
        packet.setAccessToken("x".repeat(PacketCodec.PRE_AUTH_MAX_FRAME_SIZE));
        packet.setConnectionRole(ConnectionRole.CONTROL);
        ByteBuf encoded = Unpooled.buffer();
        try {
            ProtocolException exception = assertThrows(
                    ProtocolException.class,
                    () -> PacketCodec.INSTANCE.encode(encoded, packet));
            assertEquals(ProtocolException.Reason.INVALID_LENGTH, exception.getReason());
        } finally {
            encoded.release();
        }
    }

    private static ByteBuf frame(int version, byte serializer, byte command, byte[] body) {
        return Unpooled.buffer(PacketCodec.HEADER_SIZE + body.length)
                .writeInt(PacketCodec.MAGIC_NUMBER)
                .writeByte(version)
                .writeByte(serializer)
                .writeByte(command)
                .writeInt(body.length)
                .writeBytes(body);
    }
}
