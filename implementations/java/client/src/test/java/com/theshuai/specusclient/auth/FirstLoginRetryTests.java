package com.theshuai.specusclient.auth;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import static org.assertj.core.api.Assertions.*;

class FirstLoginRetryTests {
    @Test void publicDeadlinePreservesPermanentFailureIdentityAndExitCode() {
        var failure = HttpLoginFailure.forStatus(401);
        Throwable actual = catchThrowable(() -> FirstLoginRetry.login(Duration.ofSeconds(5), remaining -> {
            throw failure;
        }, ignored -> { }));
        assertThat(actual).isSameAs(failure).hasNoCause();
        assertThat(failure.exitCode()).isEqualTo(3);
    }

    @Test void publicDeadlinePreservesCallerInterruptionAndStopsItsWorker() throws Exception {
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var stopped = new java.util.concurrent.CountDownLatch(1);
        var outcome = new java.util.concurrent.atomic.AtomicReference<Throwable>();
        var interrupted = new java.util.concurrent.atomic.AtomicBoolean();
        Thread caller = new Thread(() -> {
            outcome.set(catchThrowable(() -> FirstLoginRetry.login(Duration.ofSeconds(30), remaining -> {
                entered.countDown();
                try { release.await(); }
                catch (InterruptedException cancelled) { Thread.currentThread().interrupt(); }
                finally { stopped.countDown(); }
                return "cancelled attempt must not succeed";
            }, ignored -> { })));
            interrupted.set(Thread.currentThread().isInterrupted());
        }, "owned-login-caller-test");
        caller.start();
        try {
            assertThat(entered.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            caller.interrupt();
            caller.join(5_000);
            assertThat(caller.isAlive()).isFalse();
            assertThat(outcome.get()).isInstanceOf(HttpLoginFailure.class).hasMessage("HTTP login cancelled.");
            assertThat(interrupted.get()).isTrue();
        } finally {
            release.countDown();
            caller.interrupt();
            caller.join(5_000);
            assertThat(caller.isAlive()).isFalse();
            assertThat(stopped.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test void publicBudgetBoundsPreparationEvenWhenTheAttemptIgnoresInterrupts() throws Exception {
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var stopped = new java.util.concurrent.CountDownLatch(1);
        var caller = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            var result = caller.submit(() -> FirstLoginRetry.login(Duration.ofMillis(500), remaining -> {
                entered.countDown();
                // Models the observed default TLS trust-store initialization: it can keep
                // doing CPU/native/file work after a deadline, rather than an HTTP exchange
                // whose future can be cancelled. The test always releases its own attempt.
                try {
                    while (true) {
                        try { release.await(); break; }
                        catch (InterruptedException ignored) { /* deliberately uncooperative */ }
                    }
                    return "must not authenticate after the deadline";
                } finally { stopped.countDown(); }
            }, ignored -> { }));
            assertThat(entered.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            assertThatThrownBy(() -> result.get(2, java.util.concurrent.TimeUnit.SECONDS))
                    .isInstanceOf(java.util.concurrent.ExecutionException.class)
                    .hasCauseInstanceOf(HttpLoginFailure.class)
                    .hasRootCauseMessage("Initial HTTP login timeout. Check network/server availability or increase --login-timeout (seconds).");
            assertThat(stopped.getCount()).as("caller must time out before blocked preparation returns").isEqualTo(1);
        } finally {
            release.countDown();
            caller.shutdownNow();
            assertThat(caller.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            assertThat(stopped.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test void respectsRetryAfterWithoutExtendingTheLoginBudget() {
        var clock = new AtomicLong();
        var attempts = new AtomicInteger();
        assertThatThrownBy(() -> FirstLoginRetry.login(Duration.ofSeconds(3), remaining -> {
            attempts.incrementAndGet();
            throw HttpLoginFailure.forStatus(429, "120");
        }, ignored -> { }, clock::get, ms -> clock.addAndGet(ms * 1_000_000)))
                .hasMessageContaining("Initial HTTP login timeout");
        assertThat(attempts.get()).isEqualTo(1);
        assertThat(clock.get()).isEqualTo(3_000_000_000L);
        assertThat(HttpLoginFailure.forStatus(503, "invalid").retryAfterMillis()).isZero();
        assertThat(HttpLoginFailure.forStatus(401, "120").retryAfterMillis()).isZero();
    }

    @Test void retriesTransientFailuresWithRemainingBudget() {
        var clock = new AtomicLong();
        var attempts = new AtomicInteger();
        var budgets = new ArrayList<Duration>();
        String result = FirstLoginRetry.login(Duration.ofSeconds(10), remaining -> {
            budgets.add(remaining);
            if (attempts.incrementAndGet() < 3) throw HttpLoginFailure.forStatus(503);
            return "connected";
        }, ignored -> { }, clock::get, ms -> clock.addAndGet(ms * 1_000_000));
        assertThat(result).isEqualTo("connected");
        assertThat(budgets).containsExactly(Duration.ofSeconds(10), Duration.ofSeconds(9), Duration.ofSeconds(7));
    }

    @Test void failureBudgetIncludesAttemptsAndCappedBackoff() {
        var clock = new AtomicLong();
        var attempts = new AtomicInteger();
        assertThatThrownBy(() -> FirstLoginRetry.login(Duration.ofSeconds(2), remaining -> {
            attempts.incrementAndGet();
            clock.addAndGet(500_000_000);
            throw HttpLoginFailure.forStatus(429);
        }, ignored -> { }, clock::get, ms -> clock.addAndGet(ms * 1_000_000)))
                .hasMessageContaining("Initial HTTP login timeout");
        assertThat(attempts.get()).isEqualTo(2);
        assertThat(clock.get()).isEqualTo(2_000_000_000L);
    }

    @Test void rejectsPermanentFailuresWithoutSleeping() {
        for (int code : new int[]{301, 400, 401, 403, 404, 422}) {
            assertThatThrownBy(() -> FirstLoginRetry.login(Duration.ofSeconds(60), remaining -> {
                throw HttpLoginFailure.forStatus(code);
            }, ignored -> { }, () -> 0L, ms -> { throw new AssertionError("Must not retry"); }))
                    .hasMessageContaining("HTTP " + code);
        }
        for (int code : new int[]{408, 425, 429, 500, 502, 503, 504})
            assertThat(HttpLoginFailure.forStatus(code).isRetryable()).isTrue();
    }

    @Test void cancellationPreservesInterruptAndStopsRetrying() {
        try {
            assertThatThrownBy(() -> FirstLoginRetry.login(Duration.ofSeconds(60), remaining -> {
                throw HttpLoginFailure.forStatus(503);
            }, ignored -> { }, () -> 0L, ms -> { throw new InterruptedException(); }))
                    .hasMessageContaining("cancelled");
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally { Thread.interrupted(); }
    }
}
