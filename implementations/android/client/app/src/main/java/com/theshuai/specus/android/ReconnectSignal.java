package com.theshuai.specus.android;

/** One retained wakeup, not a second reconnect worker. Uses monotonic time. */
final class ReconnectSignal {
    private boolean pending;
    private long lastRequest;
    private boolean requested;

    synchronized boolean request() {
        long now = System.nanoTime();
        if (requested && now - lastRequest < 2_000_000_000L) return false;
        requested = true;
        lastRequest = now;
        pending = true;
        notifyAll();
        return true;
    }

    synchronized void await(long millis) throws InterruptedException {
        long end = System.nanoTime() + millis * 1_000_000L;
        while (!pending) {
            long left = end - System.nanoTime();
            if (left <= 0) return;
            wait(Math.max(1, left / 1_000_000L));
        }
        pending = false;
    }

    static long delayMillis(int attempt, double jitter) {
        long ceiling = Math.min(2L << Math.min(Math.max(attempt - 1, 0), 5), 60L) * 1000;
        return (long) (ceiling * (0.75 + 0.25 * Math.max(0, Math.min(1, jitter))));
    }
}
