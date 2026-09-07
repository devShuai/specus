package com.theshuai.specusclient.auth;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import static org.assertj.core.api.Assertions.*;

class FirstLoginRetryTests {
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
