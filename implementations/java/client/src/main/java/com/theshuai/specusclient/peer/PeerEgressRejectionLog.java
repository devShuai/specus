package com.theshuai.specusclient.peer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Refusal accounting for the egress side.
 *
 * <p>Two jobs that must not be conflated. The {@code egress-report} carries a count per error code
 * and nothing else: no destination, no domain, no payload. A report that named destinations would
 * hand the server a browsing history it has no reason to hold, so the aggregate is the only thing
 * that leaves this node.
 *
 * <p>Local diagnostic logging may name the destination, because it stays on the operator's own
 * machine. It is rate limited by subject and reason, so a consumer retrying a refused flow in a
 * loop cannot bury the one refusal an operator needs to see.
 *
 * <p>Time arrives as an argument, so the windows are deterministic under test. Not safe for
 * concurrent use; the data plane serialises access through its own loop.
 */
final class PeerEgressRejectionLog {

    /**
     * Bounds diagnostic lines for one subject and reason. Twenty a minute is enough to show a
     * pattern; the count in the suppression note carries the volume.
     */
    static final long WINDOW_MS = 60_000L;

    static final int PER_WINDOW = 20;

    /**
     * The process-wide hard cap the spec requires on the audit cache. Without it a peer that varies
     * its identity turns a rate limiter into a memory leak, which is a worse outcome than the
     * flooding the limiter exists to prevent.
     */
    static final int MAX_SUBJECTS = 4096;

    /** Whether to write a diagnostic line, and how many refusals it stands for beyond itself. */
    record Decision(boolean shouldLog, long suppressed) {
        private static final Decision SILENT = new Decision(false, 0);
    }

    private record Key(long consumer, String code) {
    }

    private static final class Bucket {
        long startedAtMs;
        int logged;
        /**
         * Refusals dropped since the last line that was emitted, so that line can say how much it
         * stands for instead of leaving the gap unexplained.
         */
        long suppressed;

        Bucket(long startedAtMs) {
            this.startedAtMs = startedAtMs;
        }
    }

    private Map<String, Long> counts = new LinkedHashMap<>();
    private final Map<Key, Bucket> recent = new LinkedHashMap<>();
    private long total;
    private boolean limited;

    /** How many refusals the current interval has seen, across every code. */
    long total() {
        return total;
    }

    /** Whether the subject cap dropped a diagnostic line during this interval. */
    boolean limited() {
        return limited;
    }

    /** How many subject-and-reason pairs the rate limiter is currently tracking. */
    int subjectCount() {
        return recent.size();
    }

    /**
     * Registers one refusal.
     *
     * <p>The aggregate is incremented unconditionally: rate limiting governs what an operator
     * reads, never what the report counts. A report that undercounted because logging was busy
     * would be worse than no report, since it would look like the refusals stopped.
     */
    Decision record(long consumer, String code, long nowMs) {
        counts.merge(code, 1L, Long::sum);
        total++;

        Key key = new Key(consumer, code);
        Bucket bucket = recent.get(key);
        if (bucket == null) {
            if (recent.size() >= MAX_SUBJECTS) {
                sweep(nowMs);
            }
            if (recent.size() >= MAX_SUBJECTS) {
                // At the cap with every window still live. The refusal stays in the aggregate, so
                // nothing is lost from the report; only the diagnostic line is dropped.
                limited = true;
                return Decision.SILENT;
            }
            bucket = new Bucket(nowMs);
            recent.put(key, bucket);
        }

        if (nowMs - bucket.startedAtMs >= WINDOW_MS) {
            bucket.startedAtMs = nowMs;
            bucket.logged = 0;
        }
        if (bucket.logged >= PER_WINDOW) {
            bucket.suppressed++;
            return Decision.SILENT;
        }
        bucket.logged++;
        long suppressed = bucket.suppressed;
        bucket.suppressed = 0;
        return new Decision(true, suppressed);
    }

    /**
     * Drops windows that have already elapsed. Called only when the cap is reached, because until
     * then an expired window costs one map entry and reusing it costs nothing.
     */
    private void sweep(long nowMs) {
        List<Key> elapsed = new ArrayList<>();
        for (Map.Entry<Key, Bucket> entry : recent.entrySet()) {
            if (nowMs - entry.getValue().startedAtMs >= WINDOW_MS) {
                elapsed.add(entry.getKey());
            }
        }
        for (Key key : elapsed) {
            recent.remove(key);
        }
    }

    /**
     * Returns the per-code totals for one {@code egress-report} and resets them, so consecutive
     * reports describe consecutive intervals rather than a running sum the server has to
     * difference.
     */
    Map<String, Long> drainCounts() {
        if (counts.isEmpty()) {
            return Map.of();
        }
        Map<String, Long> drained = counts;
        counts = new LinkedHashMap<>();
        total = 0;
        limited = false;
        return drained;
    }
}
