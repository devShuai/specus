package com.theshuai.common.serialize.impl;

import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.request.HttpRequestPacket;
import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.serialize.Serializer;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.List;
import java.util.UUID;

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
    void shouldCompressLargeHttpBody() {
        HttpRequestPacket packet = new HttpRequestPacket();
        packet.setClientName("Demo client");
        packet.setToClientName("server");
        packet.setRequestId(UUID.randomUUID().toString());
        packet.setRequestMethod("POST");
        packet.setRequestUrl("http://127.0.0.1:8080/api/demo");
        packet.setHeaderMap(Map.of("Content-Type", "application/json"));
        packet.setParamMap(Map.of("source", "tunnel"));
        packet.setBody("{\"message\":\"" + "compact-binary-serializer-".repeat(100) + "\"}");

        byte[] compactBytes = Serializer.COMPACT_BINARY.serialize(packet);
        byte[] jsonBytes = Serializer.FASTJSON.serialize(packet);
        HttpRequestPacket result = Serializer.COMPACT_BINARY.deserialize(HttpRequestPacket.class, compactBytes);

        assertEquals(packet, result);
        assertTrue(compactBytes.length < jsonBytes.length / 2);
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
    void shouldKeepSmallPayloadRaw() {
        byte[] payload = {1, 2, 3, 4};

        byte[] encoded = CompactBinarySerializer.encodePayload(payload);

        assertEquals(0, encoded[0]);
        assertArrayEquals(payload, CompactBinarySerializer.decodePayload(encoded));
    }

    @Test
    void shouldCompressNatTunnelDataWhenBeneficial() throws Exception {
        NatMessagePacket expected = new NatMessagePacket();
        expected.setNatMessageType(NatMessageType.DATA);
        expected.setMetaData(Map.of("channelId", "demo-channel"));
        expected.setData("compact-tunnel-data-".repeat(100).getBytes(StandardCharsets.UTF_8));

        ByteBuf byteBuf = Unpooled.buffer();
        try {
            PacketCodec.INSTANCE.encode(byteBuf, expected);
            assertTrue(byteBuf.readableBytes() < expected.getData().length);

            NatMessagePacket result = assertInstanceOf(NatMessagePacket.class, PacketCodec.INSTANCE.decode(byteBuf));

            assertEquals(expected.getNatMessageType(), result.getNatMessageType());
            assertEquals(expected.getMetaData(), result.getMetaData());
            assertArrayEquals(expected.getData(), result.getData());
        } finally {
            byteBuf.release();
        }
    }

    @Test
    void shouldRoundTripDirectHttpPacketsWithBinaryBodies() {
        DirectHttpRequestPacket request = new DirectHttpRequestPacket();
        request.setRequestId(UUID.randomUUID().toString());
        request.setRequestMethod("PATCH");
        request.setRoute("web");
        request.setRelativePath("/api/files/demo.bin");
        request.setRawQuery("download=true");
        request.setHeaders(List.of("Content-Type:application/octet-stream", "X-Demo:first", "X-Demo:second"));
        request.setBody(new byte[]{0, 1, 2, 3, -1});

        DirectHttpResponsePacket response = new DirectHttpResponsePacket();
        response.setRequestId(request.getRequestId());
        response.setStatusCode(206);
        response.setHeaders(List.of("Content-Type:application/octet-stream", "Set-Cookie:a=1", "Set-Cookie:b=2"));
        response.setBody(new byte[]{9, 8, 7, 6});

        assertEquals(request, Serializer.COMPACT_BINARY.deserialize(
                DirectHttpRequestPacket.class,
                Serializer.COMPACT_BINARY.serialize(request)
        ));
        assertEquals(response, Serializer.COMPACT_BINARY.deserialize(
                DirectHttpResponsePacket.class,
                Serializer.COMPACT_BINARY.serialize(response)
        ));
    }

    @Test
    void shouldEncodeAndDecodeDirectHttpPacket() throws Exception {
        DirectHttpRequestPacket expected = new DirectHttpRequestPacket();
        expected.setRequestId(UUID.randomUUID().toString());
        expected.setRequestMethod("POST");
        expected.setRoute("web");
        expected.setRelativePath("/api/upload");
        expected.setHeaders(List.of("Content-Type:application/octet-stream"));
        expected.setBody(new byte[]{1, 2, 3});

        ByteBuf byteBuf = Unpooled.buffer();
        try {
            PacketCodec.INSTANCE.encode(byteBuf, expected);
            assertEquals(expected, assertInstanceOf(DirectHttpRequestPacket.class, PacketCodec.INSTANCE.decode(byteBuf)));
        } finally {
            byteBuf.release();
        }
    }

    private LoginRequestPacket createLoginPacket() {
        LoginRequestPacket packet = new LoginRequestPacket();
        packet.setClientName("Demo client");
        packet.setPassword("test1234");
        packet.setTimestamp("1748620800000");
        packet.setCheckSign("0123456789abcdef0123456789abcdef");
        return packet;
    }
}
