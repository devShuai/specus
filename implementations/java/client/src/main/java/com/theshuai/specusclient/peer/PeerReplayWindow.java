package com.theshuai.specusclient.peer;

final class PeerReplayWindow {
    static final int WINDOW_SIZE = 4096;
    private static final int WINDOW_MASK = WINDOW_SIZE - 1;

    private long highestSequence;
    private final long[] receivedSequences = new long[WINDOW_SIZE];

    synchronized boolean accept(long sequence) {
        if (sequence <= 0) {
            return false;
        }
        if (highestSequence != 0 && sequence <= highestSequence - WINDOW_SIZE) {
            return false;
        }
        int slot = (int) sequence & WINDOW_MASK;
        if (receivedSequences[slot] == sequence) {
            return false;
        }
        receivedSequences[slot] = sequence;
        if (sequence > highestSequence) {
            highestSequence = sequence;
        }
        return true;
    }

    synchronized PeerReplayWindow copy() {
        PeerReplayWindow copy = new PeerReplayWindow();
        copy.highestSequence = highestSequence;
        System.arraycopy(receivedSequences, 0, copy.receivedSequences, 0, receivedSequences.length);
        return copy;
    }
}
