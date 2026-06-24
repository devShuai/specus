package com.theshuai.tunnelclient.peer;

final class PeerReplayWindow {
    private static final int WINDOW_SIZE = Long.SIZE;

    private long highestSequence = -1;
    private long receivedBits;

    synchronized boolean accept(long sequence) {
        if (sequence <= 0) {
            return false;
        }
        if (highestSequence < 0) {
            highestSequence = sequence;
            receivedBits = 1L;
            return true;
        }
        if (sequence > highestSequence) {
            long shift = sequence - highestSequence;
            receivedBits = shift >= WINDOW_SIZE ? 1L : (receivedBits << shift) | 1L;
            highestSequence = sequence;
            return true;
        }
        long delta = highestSequence - sequence;
        if (delta >= WINDOW_SIZE) {
            return false;
        }
        long bit = 1L << delta;
        if ((receivedBits & bit) != 0) {
            return false;
        }
        receivedBits |= bit;
        return true;
    }

    synchronized PeerReplayWindow copy() {
        PeerReplayWindow copy = new PeerReplayWindow();
        copy.highestSequence = highestSequence;
        copy.receivedBits = receivedBits;
        return copy;
    }
}
