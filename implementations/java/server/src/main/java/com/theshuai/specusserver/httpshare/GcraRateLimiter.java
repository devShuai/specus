package com.theshuai.specusserver.httpshare;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Generic cell rate algorithm, identical to the service connectivity check: one theoretical
 * arrival time (TAT) per key in integer ms, {@code tolerance = (burst - 1) * interval}. A request at
 * {@code now} conforms when {@code now >= TAT - tolerance}; conforming moves TAT to
 * {@code max(TAT, now) + interval}. A refused request consumes nothing. State is per instance.
 */
public final class GcraRateLimiter {
    private final long intervalMs;
    private final long toleranceMs;
    private final int maxKeys;
    private final Map<String, Long> theoreticalArrivals = new HashMap<>();

    public GcraRateLimiter(long intervalMs, int burst, int maxKeys) {
        if (intervalMs <= 0 || burst <= 0 || maxKeys <= 0) {
            throw new IllegalArgumentException("interval, burst and maxKeys must be positive");
        }
        this.intervalMs = intervalMs;
        this.toleranceMs = (burst - 1L) * intervalMs;
        this.maxKeys = maxKeys;
    }

    /**
     * Charges one request for {@code key} at {@code nowMs}. Returns 0 when it is admitted, else the
     * wait in ms before it would be. When the table is full, entries whose TAT is not after
     * {@code now} are evicted; if none is, a new key is refused rather than evicting a live entry.
     */
    public synchronized long tryAcquire(String key, long nowMs) {
        Long tat = theoreticalArrivals.get(key);
        if (tat == null && theoreticalArrivals.size() >= maxKeys) {
            evictIdle(nowMs);
            if (theoreticalArrivals.size() >= maxKeys) {
                return intervalMs;
            }
        }
        long current = tat == null ? nowMs : tat;
        long wait = Math.max(0, current - toleranceMs - nowMs);
        if (wait > 0) {
            return wait;
        }
        theoreticalArrivals.put(key, Math.max(current, nowMs) + intervalMs);
        return 0;
    }

    /** {@code Retry-After} for a refusal: the wait rounded up to whole seconds, at least 1. */
    public static long retryAfterSeconds(long waitMs) {
        return Math.max(1, (waitMs + 999) / 1000);
    }

    public synchronized void clear() {
        theoreticalArrivals.clear();
    }

    private void evictIdle(long nowMs) {
        Iterator<Map.Entry<String, Long>> entries = theoreticalArrivals.entrySet().iterator();
        while (entries.hasNext()) {
            if (entries.next().getValue() <= nowMs) {
                entries.remove();
            }
        }
    }
}
