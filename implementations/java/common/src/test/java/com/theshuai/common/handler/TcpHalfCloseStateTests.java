package com.theshuai.common.handler;

import org.junit.jupiter.api.Test;

import static com.theshuai.common.handler.TcpHalfCloseState.Transition.ACCEPTED;
import static com.theshuai.common.handler.TcpHalfCloseState.Transition.DUPLICATE;
import static com.theshuai.common.handler.TcpHalfCloseState.Transition.RESET;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TcpHalfCloseStateTests {
    @Test
    void closesOnlyAfterBothDirectionalFinOperationsComplete() {
        TcpHalfCloseState state = new TcpHalfCloseState();

        assertEquals(ACCEPTED, state.beginLocalFin());
        assertFalse(state.canSendLocalData());
        assertTrue(state.canReceiveRemoteData());
        state.completeLocalFin();
        assertFalse(state.isGracefullyComplete());

        assertEquals(ACCEPTED, state.receiveRemoteFin());
        assertTrue(state.isGracefulClosing());
        assertFalse(state.canReceiveRemoteData());
        assertFalse(state.isGracefullyComplete());

        state.completeRemoteOutputShutdown();
        assertTrue(state.isGracefullyComplete());
        assertEquals(DUPLICATE, state.receiveRemoteFin());
        assertEquals(DUPLICATE, state.beginLocalFin());
    }

    @Test
    void resetIsTerminalAndSuppressesFin() {
        TcpHalfCloseState state = new TcpHalfCloseState();

        assertTrue(state.reset());
        assertFalse(state.reset());
        assertEquals(RESET, state.beginLocalFin());
        assertEquals(RESET, state.receiveRemoteFin());
        assertFalse(state.canSendLocalData());
        assertFalse(state.canReceiveRemoteData());
        assertFalse(state.isGracefulClosing());
        assertFalse(state.isGracefullyComplete());
    }
}
