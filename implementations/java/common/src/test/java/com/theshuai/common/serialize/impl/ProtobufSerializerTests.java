package com.theshuai.common.serialize.impl;

import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.ProtocolException;
import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.serialize.Serializer;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProtobufSerializerTests {

    @Test
    void shouldSerializeAndDeserializePojo() {
        LoginRequestPacket packet = createPacket();

        byte[] bytes = Serializer.PROTOBUF.serialize(packet);
        LoginRequestPacket result = Serializer.PROTOBUF.deserialize(LoginRequestPacket.class, bytes);

        assertLoginPacket(result);
    }

    @Test
    void shouldRejectProtobufOnControlProtocolV2() {
        ByteBuf byteBuf = Unpooled.buffer();
        try {
            ProtocolException exception = assertThrows(
                    ProtocolException.class,
                    () -> PacketCodec.INSTANCE.encode(byteBuf, createPacket(), Serializer.PROTOBUF));
            assertEquals(ProtocolException.Reason.UNSUPPORTED_SERIALIZER, exception.getReason());
        } finally {
            byteBuf.release();
        }
    }

    private LoginRequestPacket createPacket() {
        LoginRequestPacket packet = new LoginRequestPacket();
        packet.setClientName("Demo client");
        packet.setClientSessionId(123456789L);
        packet.setAccessToken("cs_test_access_token");
        packet.setConnectionRole(ConnectionRole.CONTROL);
        return packet;
    }

    private void assertLoginPacket(LoginRequestPacket packet) {
        assertEquals("Demo client", packet.getClientName());
        assertEquals(123456789L, packet.getClientSessionId());
        assertEquals("cs_test_access_token", packet.getAccessToken());
        assertEquals(ConnectionRole.CONTROL, packet.getConnectionRole());
    }
}
