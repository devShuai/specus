package com.theshuai.specusserver.http;

import com.theshuai.common.handler.StreamFlowController;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpStreamExchangeTests {
    @Test
    void preservesDeclaredResponseTrailerNames() throws Exception {
        HttpStreamExchange exchange = new HttpStreamExchange(3);
        assertTrue(exchange.onResponseHead(Map.of(
                "source", "http",
                "phase", "response",
                "statusCode", 200,
                "headers", java.util.List.of("Content-Type:text/plain"),
                "trailerNames", java.util.List.of("Digest"))));

        HttpStreamExchange.ResponseHead head = exchange.awaitResponseHead(1_000);
        assertEquals(java.util.List.of("Digest"), head.trailerNames());
    }

    @Test
    void rejectsUndeclaredForbiddenAndInjectedResponseTrailers() throws Exception {
        HttpStreamExchange exchange = new HttpStreamExchange(4);
        assertTrue(exchange.onResponseHead(Map.of(
                "source", "http",
                "phase", "response",
                "statusCode", 200,
                "trailerNames", java.util.List.of(
                        "Digest", "Content-Length", "X-Injected", "digest"))));
        assertTrue(exchange.onFin(Map.of("trailers", java.util.List.of(
                "Digest:sha-256=valid",
                "X-Undeclared:must-not-cross",
                "Content-Length:999",
                "X-Injected:ok\r\nX-Evil: yes"))));

        HttpStreamExchange.End end = assertInstanceOf(HttpStreamExchange.End.class, exchange.take());
        assertEquals(java.util.List.of("Digest:sha-256=valid"), end.trailers());
    }

    @Test
    void buffersFragmentedResponseWithinFlowControlWindowAndPreservesFin() throws Exception {
        HttpStreamExchange exchange = new HttpStreamExchange(1);
        assertTrue(exchange.onResponseHead(Map.of(
                "source", "http",
                "phase", "response",
                "statusCode", 200,
                "trailerNames", java.util.List.of("x-checksum"))));
        byte[] fragment = new byte[4 * 1024];
        int fragments = (int) (StreamFlowController.INITIAL_WINDOW_BYTES / fragment.length);

        for (int index = 0; index < fragments; index++) {
            assertTrue(exchange.onData(fragment));
        }
        assertTrue(exchange.onFin(Map.of("trailers", java.util.List.of("x-checksum:ok"))));
        assertFalse(exchange.onFin(Map.of()));

        for (int index = 0; index < fragments; index++) {
            assertInstanceOf(HttpStreamExchange.Data.class, exchange.take());
        }
        HttpStreamExchange.End end = assertInstanceOf(HttpStreamExchange.End.class, exchange.take());
        assertEquals(java.util.List.of("x-checksum:ok"), end.trailers());
    }

    @Test
    void rejectsDataBeyondUnconsumedFlowControlWindow() {
        HttpStreamExchange exchange = new HttpStreamExchange(2);
        assertTrue(exchange.onResponseHead(Map.of(
                "source", "http",
                "phase", "response",
                "statusCode", 200)));
        byte[] frame = new byte[StreamFlowController.MAX_DATA_FRAME_BYTES];
        int frames = (int) (StreamFlowController.INITIAL_WINDOW_BYTES / frame.length);

        for (int index = 0; index < frames; index++) {
            assertTrue(exchange.onData(frame));
        }
        assertFalse(exchange.onData(new byte[]{1}));
    }

    @Test
    void requiresExactlyOneResponseHeadBeforeBodyAndTerminalFrames() {
        assertFalse(new HttpStreamExchange(5).onData(new byte[]{1}));
        assertFalse(new HttpStreamExchange(6).onFin(Map.of()));

        HttpStreamExchange exchange = new HttpStreamExchange(7);
        Map<String, Object> responseHead = Map.of(
                "source", "http",
                "phase", "response",
                "statusCode", 200);
        assertTrue(exchange.onResponseHead(responseHead));
        assertFalse(exchange.onResponseHead(responseHead));
        assertTrue(exchange.onData(new byte[]{1}));
        assertTrue(exchange.onFin(Map.of()));
        assertFalse(exchange.onFin(Map.of()));
        assertFalse(exchange.onData(new byte[]{2}));
        assertFalse(exchange.onResponseHead(responseHead));

        HttpStreamExchange reset = new HttpStreamExchange(8);
        reset.onReset(8, Map.of("reason", "cancelled"));
        assertFalse(reset.onResponseHead(responseHead));
        assertFalse(reset.onData(new byte[]{1}));
        assertFalse(reset.onFin(Map.of()));
    }
}
