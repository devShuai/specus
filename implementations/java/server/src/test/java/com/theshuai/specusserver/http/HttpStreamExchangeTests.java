package com.theshuai.specusserver.http;

import com.theshuai.common.handler.StreamFlowController;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    /**
     * The client's RST hands its failure classification to whoever waits for the head (the
     * connectivity check); a reset of this server's own, or of the connection, never carries one.
     */
    @Test
    void aClientResetCarriesItsFailureToTheHeadWaiter() {
        HttpStreamExchange peer = new HttpStreamExchange(9);
        peer.onReset(26, Map.of("reason", "dial tcp 10.0.0.1:80: refused", "failure", "connect-refused"));
        HttpStreamExchange.HttpStreamException reset = resetOf(peer);
        assertEquals(HttpStreamExchange.ResetOrigin.PEER, reset.origin());
        assertEquals("connect-refused", reset.failure());
        assertEquals(26, reset.errorCode());

        HttpStreamExchange unclassified = new HttpStreamExchange(10);
        unclassified.onReset(26, Map.of("reason", "refused"));
        assertNull(resetOf(unclassified).failure());

        for (HttpStreamExchange.ResetOrigin origin : new HttpStreamExchange.ResetOrigin[]{
                HttpStreamExchange.ResetOrigin.LOCAL, HttpStreamExchange.ResetOrigin.CONNECTION}) {
            HttpStreamExchange ours = new HttpStreamExchange(11);
            ours.onReset(8, Map.of("reason", "cancelled", "failure", "connect-refused"), origin);
            assertEquals(origin, resetOf(ours).origin());
            assertNull(resetOf(ours).failure());
        }
    }

    @Test
    void theResponseEndsOnlyWithItsFin() {
        HttpStreamExchange exchange = new HttpStreamExchange(12);
        assertFalse(exchange.responseEnded());
        assertTrue(exchange.onResponseHead(Map.of("source", "http", "phase", "response", "statusCode", 204)));
        assertFalse(exchange.responseEnded());
        assertTrue(exchange.onFin(Map.of()));
        assertTrue(exchange.responseEnded());

        HttpStreamExchange reset = new HttpStreamExchange(13);
        assertTrue(reset.onResponseHead(Map.of("source", "http", "phase", "response", "statusCode", 204)));
        reset.onReset(8, Map.of("reason", "cancelled"));
        assertFalse(reset.responseEnded());
    }

    private static HttpStreamExchange.HttpStreamException resetOf(HttpStreamExchange exchange) {
        ExecutionException ended = assertThrows(ExecutionException.class, () -> exchange.awaitResponseHead(1_000));
        return assertInstanceOf(HttpStreamExchange.HttpStreamException.class, ended.getCause());
    }
}
