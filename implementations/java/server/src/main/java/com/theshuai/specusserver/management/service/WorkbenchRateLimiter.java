package com.theshuai.specusserver.management.service;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * GCRA limiter for the workbench's growth operations (adding a favourite, recording an open), one
 * theoretical arrival time (TAT) per identity, per instance (protocol/spec/service-workbench.md
 * section 7). Removal and clearing never come here.
 *
 * <p>interval 1000 ms, burst 30, tolerance (burst - 1) * interval. A request at {@code now} conforms
 * when {@code now >= TAT - tolerance}; conforming moves TAT to {@code max(TAT, now) + interval}. A
 * refused request consumes nothing. At most {@value #MAX_KEYS} keys are tracked: an entry whose TAT
 * is not after {@code now} equals no entry and is evicted when a new key needs room; when every entry
 * is still live the new key is refused with a one-second retry.
 */
@Component
public class WorkbenchRateLimiter {
    static final long INTERVAL_MS = 1_000L;
    static final int BURST = 30;
    static final long TOLERANCE_MS = (BURST - 1) * INTERVAL_MS;
    static final int MAX_KEYS = 10_000;

    private final Map<String, Long> theoreticalArrivals = new HashMap<>();

    /**
     * Admits or refuses one growth request of the identity.
     *
     * @return 0 when admitted (the request is charged), otherwise the Retry-After in whole seconds
     */
    public synchronized long acquire(String tenantId, String username, long now) {
        String key = tenantId + "\n" + username;
        Long stored = theoreticalArrivals.get(key);
        if (stored == null && theoreticalArrivals.size() >= MAX_KEYS) {
            theoreticalArrivals.values().removeIf(tat -> tat <= now);
            if (theoreticalArrivals.size() >= MAX_KEYS) {
                return 1;
            }
        }
        long tat = stored == null ? now : stored;
        long waitMs = Math.max(0L, tat - TOLERANCE_MS - now);
        if (waitMs > 0) {
            return Math.max(1L, Math.ceilDiv(waitMs, 1_000L));
        }
        theoreticalArrivals.put(key, Math.max(tat, now) + INTERVAL_MS);
        return 0;
    }

    /** Forgets every key; tests start each scenario from an empty limiter. */
    public synchronized void clear() {
        theoreticalArrivals.clear();
    }
}
