package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.StreamFlowController;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Bytes one stream has received from the server but not yet handed to its local socket.
 *
 * <p>Credit goes back to the server only once a write to the local socket completes, so a server
 * that honours the window never has more than the initial window outstanding on one stream. That
 * bound is the stream's backpressure: the data connection is never paused on its behalf, because
 * pausing the connection for one slow upstream stalls every other stream multiplexed on it,
 * including the one that upstream may itself be waiting on. Anything past the window is the server
 * ignoring it, and the stream is refused rather than buffered without limit. DATA held while the
 * local connect is still under way counts here too, which is what bounds that hold.
 */
final class StreamReceiveWindow {
    private final AtomicLong outstanding = new AtomicLong();

    /** Records bytes about to be written locally; false when they overrun the window. */
    boolean reserve(int bytes) {
        return outstanding.addAndGet(bytes) <= StreamFlowController.INITIAL_WINDOW_BYTES;
    }

    /** Records bytes the local socket has taken, which the caller now credits back. */
    void release(int bytes) {
        outstanding.addAndGet(-bytes);
    }
}
