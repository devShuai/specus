package com.theshuai.specusserver.connectivity;

import java.time.Instant;

/**
 * The two clocks of a connectivity check: a monotonic one for the budget, the stage times and the
 * rate limits, and the wall clock for {@code checkedAt}. Tests drive both.
 */
public interface ConnectivityCheckClock {
    ConnectivityCheckClock SYSTEM = new ConnectivityCheckClock() {
        @Override
        public long monotonicMillis() {
            return System.nanoTime() / 1_000_000L;
        }

        @Override
        public Instant now() {
            return Instant.now();
        }
    };

    /** Milliseconds from an arbitrary origin that never goes backwards. */
    long monotonicMillis();

    /** Wall-clock time. */
    Instant now();
}
