package com.theshuai.stunserver;

import java.net.InetAddress;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

final class StunRequestLimiter {
    private static final int CLEANUP_MASK = 1_023;

    private final StandaloneStunProtectionConfig config;
    private final TokenBucket global;
    private final LinkedHashMap<String, SourceBucket> sources =
            new LinkedHashMap<>(256, 0.75f, true);
    private long requestCount;

    StunRequestLimiter(StandaloneStunProtectionConfig config) {
        this.config = Objects.requireNonNull(config, "config");
        long now = System.nanoTime();
        this.global = new TokenBucket(config.globalBurst(), now);
    }

    synchronized Decision allow(InetAddress sourceAddress) {
        long now = System.nanoTime();
        requestCount++;
        if (!global.tryConsume(
                now,
                config.globalRatePerSecond(),
                config.globalBurst())) {
            return Decision.GLOBAL_RATE_LIMIT;
        }

        if ((requestCount & CLEANUP_MASK) == 0) {
            removeIdle(now);
        }
        String source = sourceAddress == null ? "unknown" : sourceAddress.getHostAddress();
        SourceBucket bucket = sources.get(source);
        if (bucket == null) {
            if (sources.size() >= config.maxTrackedSources()) {
                removeIdle(now);
            }
            if (sources.size() >= config.maxTrackedSources()) {
                return Decision.SOURCE_TABLE_FULL;
            }
            bucket = new SourceBucket(new TokenBucket(config.sourceBurst(), now), now);
            sources.put(source, bucket);
        }
        bucket.lastSeenNanos = now;
        if (!bucket.tokens.tryConsume(
                now,
                config.sourceRatePerSecond(),
                config.sourceBurst())) {
            return Decision.SOURCE_RATE_LIMIT;
        }
        return Decision.ALLOWED;
    }

    synchronized int trackedSources() {
        removeIdle(System.nanoTime());
        return sources.size();
    }

    private void removeIdle(long now) {
        long idleNanos = config.sourceIdleSeconds() * 1_000_000_000L;
        Iterator<Map.Entry<String, SourceBucket>> iterator = sources.entrySet().iterator();
        while (iterator.hasNext()) {
            SourceBucket bucket = iterator.next().getValue();
            if (now - bucket.lastSeenNanos >= idleNanos) {
                iterator.remove();
            }
        }
    }

    enum Decision {
        ALLOWED,
        GLOBAL_RATE_LIMIT,
        SOURCE_RATE_LIMIT,
        SOURCE_TABLE_FULL
    }

    private static final class SourceBucket {
        private final TokenBucket tokens;
        private long lastSeenNanos;

        private SourceBucket(TokenBucket tokens, long lastSeenNanos) {
            this.tokens = tokens;
            this.lastSeenNanos = lastSeenNanos;
        }
    }

    private static final class TokenBucket {
        private double tokens;
        private long updatedNanos;

        private TokenBucket(int burst, long now) {
            this.tokens = burst;
            this.updatedNanos = now;
        }

        private boolean tryConsume(long now, int ratePerSecond, int burst) {
            long elapsed = Math.max(0, now - updatedNanos);
            if (elapsed > 0) {
                tokens = Math.min(
                        burst,
                        tokens + elapsed * (double) ratePerSecond / 1_000_000_000D);
                updatedNanos = now;
            }
            if (tokens < 1D) {
                return false;
            }
            tokens -= 1D;
            return true;
        }
    }
}
