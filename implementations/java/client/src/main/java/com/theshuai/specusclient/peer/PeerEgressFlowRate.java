package com.theshuai.specusclient.peer;

import java.util.HashMap;
import java.util.Map;

/**
 * How fast each consumer may open new flows through this egress: one token bucket per consumer
 * (protocol/spec/peer-egress.md, resource limits; shared vectors in {@code peer-egress-rate-v1.json}).
 *
 * <p>The concurrency caps bound how many flows exist at once, not how fast a consumer churns
 * through short ones, so a port scan made of quick connections passes every one of them. This is
 * what stops it.
 *
 * <p>Tokens are counted in integer thousandths against an integer millisecond clock, so every
 * runtime lands on the same side of a boundary: a token takes 15.625 ms to come back, and 15 ms is
 * not enough anywhere.
 *
 * <p>Like the flow table, not safe for concurrent use: the data plane calls it under its own lock.
 */
final class PeerEgressFlowRate {

    static final int CAPACITY = 128;
    static final int REFILL_PER_SECOND = 64;

    private static final long FULL = CAPACITY * 1000L;
    private static final long ONE_FLOW = 1000L;
    /** How long an empty bucket takes to fill; any longer gap refills it all the same. */
    private static final long FILL_MS = FULL / REFILL_PER_SECOND;
    private static final int MIN_SWEEP = 64;

    private static final class Bucket {
        long milli;
        long atMs;
    }

    private final Map<Long, Bucket> buckets = new HashMap<>();
    private int sweepAt = MIN_SWEEP;

    /**
     * Takes a token for one new flow, or reports that the consumer has none. Only a flow every other
     * check already admitted may ask: a refused attempt must cost nothing.
     */
    boolean tryTake(long consumer, long nowMs) {
        Bucket bucket = buckets.get(consumer);
        if (bucket == null) {
            if (buckets.size() >= sweepAt) {
                sweep(nowMs);
            }
            bucket = new Bucket();
            bucket.milli = FULL;
            buckets.put(consumer, bucket);
        } else {
            bucket.milli = refilled(bucket, nowMs);
        }
        bucket.atMs = nowMs;
        if (bucket.milli < ONE_FLOW) {
            return false;
        }
        bucket.milli -= ONE_FLOW;
        return true;
    }

    private static long refilled(Bucket bucket, long nowMs) {
        // Clamped before multiplying, so no gap however long can overflow.
        long elapsed = Math.min(Math.max(0, nowMs - bucket.atMs), FILL_MS);
        return Math.min(FULL, bucket.milli + elapsed * REFILL_PER_SECOND);
    }

    /**
     * Forgets every bucket that has filled again. A full bucket and no bucket decide alike, so this
     * changes no answer; it keeps the map to the consumers that opened flows in the last two seconds
     * rather than every consumer that ever did. Run each time the map doubles, so its cost spreads
     * over the insertions that grew it.
     */
    private void sweep(long nowMs) {
        buckets.values().removeIf(bucket -> refilled(bucket, nowMs) == FULL);
        sweepAt = Math.max(MIN_SWEEP, buckets.size() * 2);
    }

    /** How many consumers hold a bucket; for tests. */
    int size() {
        return buckets.size();
    }
}
