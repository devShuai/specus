package com.theshuai.specusserver.connectivity;

import java.util.HashMap;
import java.util.Map;

/**
 * The two rate limits of the connectivity check (protocol/spec/service-connectivity-check.md
 * section 7): GCRA, one theoretical arrival time (TAT) per key in integer milliseconds.
 *
 * <ul>
 *   <li>per route, {@code tenantId + routeId}: one check per 10 s, no burst. The key has no caller
 *       in it, so an owner and an admin cannot double the probe rate of a route between them;</li>
 *   <li>per user, {@code tenantId + username}: a burst of 10, then one per 30 s.</li>
 * </ul>
 *
 * <p>A check is admitted only when both keys conform, and then takes both; a refused check changes
 * neither. Each table holds at most {@link #MAX_KEYS} keys: an entry whose TAT is not later than
 * now is the same as no entry and may be dropped, but a live entry is never evicted, because that
 * would hand its key a fresh allowance. When a new key finds the table full of live entries the
 * check is refused as busy and nothing is taken.
 */
public final class ConnectivityCheckRateLimiter {
    public static final long ROUTE_INTERVAL_MS = 10_000;
    public static final int ROUTE_BURST = 1;
    public static final long USER_INTERVAL_MS = 30_000;
    public static final int USER_BURST = 10;
    public static final int MAX_KEYS = 10_000;

    private final Gcra perRoute;
    private final Gcra perUser;

    public ConnectivityCheckRateLimiter() {
        this(MAX_KEYS);
    }

    ConnectivityCheckRateLimiter(int maxKeys) {
        this.perRoute = new Gcra(ROUTE_INTERVAL_MS, ROUTE_BURST, maxKeys);
        this.perUser = new Gcra(USER_INTERVAL_MS, USER_BURST, maxKeys);
    }

    public synchronized Admission tryAcquire(String routeKey, String userKey, long nowMillis) {
        long routeWait = perRoute.waitMillis(routeKey, nowMillis);
        long userWait = perUser.waitMillis(userKey, nowMillis);
        long wait = Math.max(routeWait, userWait);
        if (wait > 0) {
            return new Admission(Outcome.LIMITED, wait, routeWait >= userWait ? "route" : "user");
        }
        if (!perRoute.hasRoomFor(routeKey, nowMillis) || !perUser.hasRoomFor(userKey, nowMillis)) {
            return new Admission(Outcome.FULL, 0, null);
        }
        perRoute.take(routeKey, nowMillis);
        perUser.take(userKey, nowMillis);
        return new Admission(Outcome.ADMITTED, 0, null);
    }

    public enum Outcome {
        ADMITTED,
        /** One of the keys does not conform yet: {@code 429 CHECK_RATE_LIMITED}. */
        LIMITED,
        /** A new key found its table full of live entries: {@code 503 CHECK_BUSY}. */
        FULL
    }

    /**
     * @param waitMillis the longer of the two waits, for a limited check
     * @param limitedBy  {@code route} or {@code user}: the key with the longer wait, the route on a tie
     */
    public record Admission(Outcome outcome, long waitMillis, String limitedBy) {
        /** Whole seconds, rounded up, at least 1. */
        public long retryAfterSeconds() {
            return Math.max(1, (waitMillis + 999) / 1000);
        }
    }

    private static final class Gcra {
        private final long interval;
        private final long tolerance;
        private final int maxKeys;
        private final Map<String, Long> theoreticalArrival = new HashMap<>();

        private Gcra(long interval, int burst, int maxKeys) {
            this.interval = interval;
            this.tolerance = (burst - 1L) * interval;
            this.maxKeys = maxKeys;
        }

        private long waitMillis(String key, long now) {
            long tat = theoreticalArrival.getOrDefault(key, now);
            return Math.max(0, tat - tolerance - now);
        }

        private boolean hasRoomFor(String key, long now) {
            if (theoreticalArrival.containsKey(key) || theoreticalArrival.size() < maxKeys) {
                return true;
            }
            theoreticalArrival.values().removeIf(tat -> tat <= now);
            return theoreticalArrival.size() < maxKeys;
        }

        private void take(String key, long now) {
            long tat = theoreticalArrival.getOrDefault(key, now);
            theoreticalArrival.put(key, Math.max(tat, now) + interval);
        }
    }
}
