package com.theshuai.specusclient.handler;

import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshaker;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshakerFactory;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketVersion;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class FramePreservingWebSocketClientProtocolHandlerTests {

    @Test
    void exposesPingPongAndCloseToTheSws2Handler() throws Exception {
        FramePreservingWebSocketClientProtocolHandler handler = handler();

        assertPreserved(handler, new PingWebSocketFrame());
        assertPreserved(handler, new PongWebSocketFrame());
        assertPreserved(handler, new CloseWebSocketFrame(1000, "done"));
    }

    private static void assertPreserved(FramePreservingWebSocketClientProtocolHandler handler,
                                        WebSocketFrame frame) throws Exception {
        List<Object> output = new ArrayList<>();
        try {
            handler.decode(null, frame, output);
            assertEquals(1, output.size());
            assertSame(frame, output.getFirst());
        } finally {
            frame.release();
            for (Object item : output) {
                if (item instanceof WebSocketFrame retained) {
                    retained.release();
                }
            }
        }
    }

    private static FramePreservingWebSocketClientProtocolHandler handler() {
        WebSocketClientHandshaker handshaker = WebSocketClientHandshakerFactory.newHandshaker(
                URI.create("ws://127.0.0.1/socket"),
                WebSocketVersion.V13,
                null,
                true,
                new DefaultHttpHeaders(),
                16 * 1024 * 1024);
        return new FramePreservingWebSocketClientProtocolHandler(handshaker);
    }
}
