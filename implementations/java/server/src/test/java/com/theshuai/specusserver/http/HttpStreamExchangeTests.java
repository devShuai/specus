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
    void buffersFragmentedResponseWithinFlowControlWindowAndPreservesFin() throws Exception {
        HttpStreamExchange exchange = new HttpStreamExchange(1);
        byte[] fragment = new byte[4 * 1024];
        int fragments = (int) (StreamFlowController.INITIAL_WINDOW_BYTES / fragment.length);

        for (int index = 0; index < fragments; index++) {
            assertTrue(exchange.onData(fragment));
        }
        exchange.onFin(Map.of("trailers", java.util.List.of("x-checksum:ok")));

        for (int index = 0; index < fragments; index++) {
            assertInstanceOf(HttpStreamExchange.Data.class, exchange.take());
        }
        HttpStreamExchange.End end = assertInstanceOf(HttpStreamExchange.End.class, exchange.take());
        assertEquals(java.util.List.of("x-checksum:ok"), end.trailers());
    }

    @Test
    void rejectsDataBeyondUnconsumedFlowControlWindow() {
        HttpStreamExchange exchange = new HttpStreamExchange(2);
        byte[] frame = new byte[StreamFlowController.MAX_DATA_FRAME_BYTES];
        int frames = (int) (StreamFlowController.INITIAL_WINDOW_BYTES / frame.length);

        for (int index = 0; index < frames; index++) {
            assertTrue(exchange.onData(frame));
        }
        assertFalse(exchange.onData(new byte[]{1}));
    }
}
