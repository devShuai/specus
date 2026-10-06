package com.theshuai.specusserver.httpshare;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Clock;

/**
 * The clock and random source of the share subsystem, plus its two per-instance rate limiters.
 * Production uses the UTC system clock and {@link SecureRandom}; tests replace both so that the
 * shared vectors' fixed instants and bytes can be replayed through the real services.
 */
@Component
public class HttpShareRuntime {
    private final SecureRandom secureRandom = new SecureRandom();
    private final GcraRateLimiter exchangeLimiter = new GcraRateLimiter(
            HttpShareRules.EXCHANGE_INTERVAL_MS, HttpShareRules.EXCHANGE_BURST, HttpShareRules.RATE_LIMIT_MAX_KEYS);
    private final GcraRateLimiter shareLimiter = new GcraRateLimiter(
            HttpShareRules.SHARE_INTERVAL_MS, HttpShareRules.SHARE_BURST, HttpShareRules.RATE_LIMIT_MAX_KEYS);
    private volatile Clock clock = Clock.systemUTC();
    private volatile HttpShareRandom random = secureRandom::nextBytes;

    public Clock clock() {
        return clock;
    }

    public long nowMillis() {
        return clock.millis();
    }

    /** Whole epoch seconds, truncated: a share is expired once {@code nowSeconds() >= expiresAt}. */
    public long nowSeconds() {
        return Math.floorDiv(clock.millis(), 1000L);
    }

    public HttpShareRandom random() {
        return random;
    }

    /** Exchange attempts per source address: 10 at once, then one every 6 s. */
    public GcraRateLimiter exchangeLimiter() {
        return exchangeLimiter;
    }

    /** Requests per share: 200 at once (a page load), then 20 per second. */
    public GcraRateLimiter shareLimiter() {
        return shareLimiter;
    }

    /** Test seam: replaces the clock ({@code null} restores the system clock). */
    public void useClock(Clock replacement) {
        this.clock = replacement == null ? Clock.systemUTC() : replacement;
    }

    /** Test seam: replaces the random source ({@code null} restores the CSPRNG). */
    public void useRandom(HttpShareRandom replacement) {
        this.random = replacement == null ? secureRandom::nextBytes : replacement;
    }
}
