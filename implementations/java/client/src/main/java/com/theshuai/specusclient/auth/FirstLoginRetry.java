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
        return login(budget, (remaining, cancelled) -> attempt.apply(remaining), diagnostic);
    }

    /** A cancellation predicate also survives preparation that swallows Thread.interrupt(). */
    public static <T> T login(Duration budget,
                             java.util.function.BiFunction<Duration, java.util.function.BooleanSupplier, T> attempt,
                             Consumer<String> diagnostic) {
        if (budget.isZero() || budget.isNegative()) throw new IllegalArgumentException("Login budget must be positive");
        if (Thread.currentThread().isInterrupted()) throw interrupted();
        // HttpClient.build() can synchronously load the platform TLS trust store before
        // sendAsync even exists. HttpRequest.timeout / future.get cannot bound that work.
        // Keep ALL initial-login preparation, attempts and backoff under one caller deadline.
        // TLS validation stays untouched. A provider/native initializer may ignore interrupt,
        // so it must not hold startup or process exit hostage on a non-daemon worker.
        var executor = java.util.concurrent.Executors.newSingleThreadExecutor(task -> {
            Thread worker = new Thread(task, "specus-initial-login");
            worker.setDaemon(true);
            return worker;
        });
        long started = System.nanoTime();
        var cancelled = new java.util.concurrent.atomic.AtomicBoolean();
        java.util.function.BooleanSupplier expired = () -> cancelled.get()
                || System.nanoTime() - started >= budget.toNanos();
        var pending = executor.submit(() -> login(budget, remaining -> attempt.apply(remaining, expired),
                diagnostic, System::nanoTime, Thread::sleep));
        try {
            long remaining = budget.toNanos() - (System.nanoTime() - started);
            if (remaining <= 0) throw exhausted();
            return pending.get(remaining, java.util.concurrent.TimeUnit.NANOSECONDS);
        } catch (java.util.concurrent.TimeoutException timeout) {
            throw exhausted();
        } catch (InterruptedException interruptedWait) {
            Thread.currentThread().interrupt();
            throw interrupted();
        } catch (java.util.concurrent.ExecutionException failed) {
            if (failed.getCause() instanceof RuntimeException error) throw error;
            if (failed.getCause() instanceof Error error) throw error;
            throw new IllegalStateException("Unexpected initial HTTP login failure", failed.getCause());
        } finally {
            cancelled.set(true);
            pending.cancel(true);
            // ExecutorService.close() waits for uncooperative preparation, undoing the bound.
            executor.shutdownNow();
        }
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
