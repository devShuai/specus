package com.theshuai.common.serialize.impl;

import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.serialize.Serializer;
import com.theshuai.common.serialize.SerializerAlgorithm;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CompactBinarySerializerTests {

    @Test
    void shouldUseLessSpaceThanJsonForLoginPacket() {
        LoginRequestPacket packet = createLoginPacket();

        byte[] compactBytes = Serializer.COMPACT_BINARY.serialize(packet);
        byte[] jsonBytes = Serializer.FASTJSON.serialize(packet);
        LoginRequestPacket result = Serializer.COMPACT_BINARY.deserialize(LoginRequestPacket.class, compactBytes);

        assertEquals(packet, result);
        assertTrue(compactBytes.length < jsonBytes.length);
    }

    @Test
    void shouldEncodeAndDecodePacketWithCompactBinaryByDefault() throws Exception {
        ByteBuf byteBuf = Unpooled.buffer();
        try {
            LoginRequestPacket expected = createLoginPacket();

            PacketCodec.INSTANCE.encode(byteBuf, expected);
            Packet packet = PacketCodec.INSTANCE.decode(byteBuf);

            assertEquals(expected, assertInstanceOf(LoginRequestPacket.class, packet));
        } finally {
            byteBuf.release();
        }
    }

    @Test
    void shouldKeepNatSpecusDataRawWithExplicitLengths() throws Exception {
        NatMessagePacket expected = new NatMessagePacket();
        expected.setNatMessageType(NatMessageType.DATA);
        expected.setStreamId(1);
        expected.setData("compact-specus-data-".repeat(100).getBytes(StandardCharsets.UTF_8));

        ByteBuf byteBuf = Unpooled.buffer();
        try {
            PacketCodec.INSTANCE.encode(byteBuf, expected);
            ByteBuf frame = byteBuf.duplicate();
            assertEquals(PacketCodec.MAGIC_NUMBER, frame.readInt());
            assertEquals(PacketCodec.PROTOCOL_VERSION, frame.readByte());
            assertEquals(SerializerAlgorithm.BIN, frame.readByte());
            frame.skipBytes(1);
            assertEquals(frame.readableBytes() - Integer.BYTES, frame.readInt());
            assertEquals(NatMessageType.DATA.getCode(), frame.readUnsignedByte());
            assertEquals(0, frame.readUnsignedByte());
            int metadataLength = frame.readUnsignedShort();
            assertEquals(0, metadataLength);
            assertEquals(1, frame.readInt());
            assertEquals(0, frame.readInt());
            assertEquals(expected.getData().length, frame.readInt());
            frame.skipBytes(metadataLength);
            byte[] wireData = new byte[frame.readableBytes()];
            frame.readBytes(wireData);
            assertArrayEquals(expected.getData(), wireData);

            NatMessagePacket result = assertInstanceOf(NatMessagePacket.class, PacketCodec.INSTANCE.decode(byteBuf));

            assertEquals(expected.getNatMessageType(), result.getNatMessageType());
            assertTrue(result.getMetaData().isEmpty());
            assertArrayEquals(expected.getData(), result.getData());
        } finally {
            byteBuf.release();
        }
    }

    @Test
    void shouldEncodeAndDecodeNatControlMessage() throws Exception {
        MessageResponsePacket expected = new MessageResponsePacket();
        expected.setClientName("Demo client");
        expected.setMessageType(MessageType.NAT_CONTROL);
        expected.setMessage("{\"clientName\":\"Demo client\",\"remotePort\":7010,"
                + "\"specusConfigList\":[{\"port\":9000,\"specusAddress\":\"127.0.0.1\",\"specusPort\":8080}]}");

        ByteBuf byteBuf = Unpooled.buffer();
        try {
            PacketCodec.INSTANCE.encode(byteBuf, expected);
            MessageResponsePacket result = assertInstanceOf(MessageResponsePacket.class, PacketCodec.INSTANCE.decode(byteBuf));

            assertEquals(MessageType.NAT_CONTROL, result.getMessageType());
            assertEquals(expected.getClientName(), result.getClientName());
            assertEquals(expected.getMessage(), result.getMessage());
        } finally {
            byteBuf.release();
        }
    }

    private LoginRequestPacket createLoginPacket() {
        LoginRequestPacket packet = new LoginRequestPacket();
        packet.setClientName("Demo client");
        packet.setClientSessionId(1748620800000L);
        packet.setAccessToken("cs_compact_binary_fixture_token");
        packet.setConnectionRole(ConnectionRole.CONTROL);
        return packet;
    }
}
