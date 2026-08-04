package com.theshuai.specus.android;

import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import org.junit.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class NettyWebSocketTransportTest {
    @Test
    public void preservesDataFrameFinRsvAndPayload() {
        WebSocketFrame frame = NettyWebSocketTransport.toNettyFrame(
                0x2, false, 5, 0, new byte[]{1, 2, 3});
        try {
            assertEquals(0x2, NettyWebSocketTransport.opcode(frame));
            assertFalse(frame.isFinalFragment());
            assertEquals(5, frame.rsv());
            byte[] payload = new byte[frame.content().readableBytes()];
            frame.content().getBytes(frame.content().readerIndex(), payload);
            assertArrayEquals(new byte[]{1, 2, 3}, payload);
        } finally {
            frame.release();
        }
    }

    @Test
    public void preservesCloseCodeAndReasonSeparately() {
        WebSocketFrame raw = NettyWebSocketTransport.toNettyFrame(
                0x8, true, 0, 1000, "done".getBytes(StandardCharsets.UTF_8));
        try {
            CloseWebSocketFrame close = (CloseWebSocketFrame) raw;
            assertEquals(0x8, NettyWebSocketTransport.opcode(close));
            assertEquals(1000, close.statusCode());
            assertEquals("done", close.reasonText());
        } finally {
            raw.release();
        }
    }

    @Test
    public void decoderAcceptsJavaReferenceFrameLimitAndPendingWritesStayBounded() {
        assertEquals(SpecusCore.WebSocketSupport.MAX_MESSAGE_BYTES,
                NettyWebSocketTransport.MAX_FRAME_BYTES);
        NettyWebSocketTransport.PendingWriteLimiter limiter =
                new NettyWebSocketTransport.PendingWriteLimiter(10L);
        assertTrue(limiter.reserve(9L));
        assertFalse(limiter.reserve(2L));
        assertEquals(9L, limiter.pendingBytes());
        limiter.release(9L);
        assertEquals(0L, limiter.pendingBytes());
        assertTrue(limiter.reserve(10L));
        assertFalse(limiter.reserve(1L));
        limiter.release(10L);
    }

    @Test
    public void closeBeforeStartNeverCreatesOrProtectsAChannel() throws Exception {
        AtomicBoolean protectedSocket = new AtomicBoolean();
        AtomicBoolean callback = new AtomicBoolean();
        NettyWebSocketTransport transport = new NettyWebSocketTransport(
                new URI("ws://127.0.0.1:9/cancelled"), null,
                socket -> protectedSocket.set(true), new NettyWebSocketTransport.Listener() {
            @Override
            public void onOpen() {
                callback.set(true);
            }

            @Override
            public void onFrame(int opcode, boolean fin, int rsv,
                                int closeCode, byte[] payload) {
                callback.set(true);
            }

            @Override
            public void onClosed(String detail) {
                callback.set(true);
            }

            @Override
            public void onFailure(Throwable error) {
                callback.set(true);
            }
        });

        transport.close();
        transport.start();

        assertFalse(protectedSocket.get());
        assertFalse(callback.get());
        assertTrue(transport.send(0x2, true, 0, 0, new byte[]{1})
                .isCompletedExceptionally());
    }
}
