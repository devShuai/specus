package com.theshuai.specusclient.peer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerReplayWindowTests {
    @Test
    void acceptsSmallOutOfOrderSequencesOnce() {
        PeerReplayWindow window = new PeerReplayWindow();

        assertTrue(window.accept(10));
        assertTrue(window.accept(12));
        assertTrue(window.accept(11));
        assertFalse(window.accept(11));
    }

    @Test
    void rejectsOldSequencesOutsideWindow() {
        PeerReplayWindow window = new PeerReplayWindow();

        assertTrue(window.accept(1));
        assertTrue(window.accept(5000));
        assertFalse(window.accept(1));
    }

    @Test
    void copiedWindowPreservesReplayState() {
        PeerReplayWindow window = new PeerReplayWindow();
        assertTrue(window.accept(5));

        PeerReplayWindow copy = window.copy();

        assertFalse(copy.accept(5));
        assertTrue(copy.accept(6));
    }
}
