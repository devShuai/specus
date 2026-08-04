package com.theshuai.specusclient.handler;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameDecoder;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NatClientHandlerWebSocketTargetTests {

    @Test
    void acceptsLocalWebSocketFramesUpToProtocolMessageLimit() {
        assertThat(NatClientHandler.LOCAL_WS_MAX_FRAME_PAYLOAD_BYTES)
                .isEqualTo(16 * 1024 * 1024);

        int payloadBytes = 64 * 1024 + 1;
        EmbeddedChannel decoder = new EmbeddedChannel(new WebSocket13FrameDecoder(
                false, false, NatClientHandler.LOCAL_WS_MAX_FRAME_PAYLOAD_BYTES));
        ByteBuf wireFrame = Unpooled.buffer(10 + payloadBytes)
                .writeByte(0x82)
                .writeByte(127)
                .writeLong(payloadBytes)
                .writeZero(payloadBytes);
        assertThat(decoder.writeInbound(wireFrame)).isTrue();
        BinaryWebSocketFrame decoded = decoder.readInbound();
        try {
            assertThat(decoded.content().readableBytes()).isEqualTo(payloadBytes);
        } finally {
            decoded.release();
            decoder.finishAndReleaseAll();
        }
    }

    @Test
    void mapsHttpSchemesAndPreservesEncodedPathAndRawQuery() {
        assertThat(NatClientHandler.buildWsTarget(
                "http://example.test/base%2Froot",
                "/%E4%BD%A0%2F%252F",
                "next=%2Fraw").toASCIIString())
                .isEqualTo("ws://example.test/base%2Froot/%E4%BD%A0%2F%252F?next=%2Fraw");

        assertThat(NatClientHandler.buildWsTarget(
                "https://example.test/base/", "/events", null).toASCIIString())
                .isEqualTo("wss://example.test/base/events");
    }

    @Test
    void rejectsPlainAndEncodedDotSegments() {
        assertRejected("/../admin");
        assertRejected("/%2e%2e/admin");
    }

    @Test
    void rejectsControlCharactersBeforeBuildingTarget() {
        assertThatThrownBy(() -> NatClientHandler.buildWsTarget(
                "http://example.test/base", "/socket\r\nBad: value", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("relativePath 含有非法控制字符");
    }

    private static void assertRejected(String relativePath) {
        assertThatThrownBy(() -> NatClientHandler.buildWsTarget(
                "http://example.test/base", relativePath, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("HTTP 转发路径越界");
    }
}
