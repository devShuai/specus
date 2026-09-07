package com.theshuai.specusclient.auth;

import java.time.Duration;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongSupplier;

/** Retry only initial HTTP authentication, not control-channel or business readiness. */
public final class FirstLoginRetry {
    private FirstLoginRetry() { }

    @FunctionalInterface interface Sleeper { void sleep(long millis) throws InterruptedException; }

    public static <T> T login(Duration budget, Function<Duration, T> attempt, Consumer<String> diagnostic) {
        return login(budget, attempt, diagnostic, System::nanoTime, Thread::sleep);
    }

    static <T> T login(Duration budget, Function<Duration, T> attempt, Consumer<String> diagnostic,
                       LongSupplier clock, Sleeper sleeper) {
        if (budget.isZero() || budget.isNegative()) throw new IllegalArgumentException("Login budget must be positive");
        long started = clock.getAsLong();
        long delay = 1_000;
        int count = 0;
        while (true) {
            if (Thread.currentThread().isInterrupted()) throw interrupted();
            long remaining = budget.toNanos() - (clock.getAsLong() - started);
            if (remaining <= 0) throw exhausted();
            try {
                return attempt.apply(Duration.ofNanos(remaining));
            } catch (HttpLoginFailure failure) {
                if (!failure.isRetryable()) throw failure;
                remaining = budget.toNanos() - (clock.getAsLong() - started);
                if (remaining <= 0) throw exhausted();
                long wait = Math.min(Math.max(delay, failure.retryAfterMillis()), Duration.ofNanos(remaining).toMillis());
                if (wait <= 0) throw exhausted();
                diagnostic.accept("HTTP login attempt " + (++count) + " failed. " + failure.getMessage()
                        + " Retrying in " + wait + " ms within the initial login budget.");
                try {
                    sleeper.sleep(wait);
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    throw interrupted();
                }
                delay = Math.min(delay * 2, 5_000);
            }
        }
    }

    private static HttpLoginFailure exhausted() {
        return new HttpLoginFailure("Initial HTTP login timeout. Check network/server availability or increase --login-timeout (seconds).", false);
    }

    private static HttpLoginFailure interrupted() {
        return new HttpLoginFailure("HTTP login cancelled.", false);
    }
}
