package com.theshuai.specusserver.security;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.service.RateLimitedException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LoginRateLimiterTests {

    @Test
    void blocksPerSourceIpAcrossDifferentAccounts() {
        LoginRateLimiter limiter = limiter(3, 100);
        for (int attempt = 1; attempt <= 3; attempt++) {
            String username = "user-" + attempt;
            assertThatCode(() -> limiter.checkLoginAttempt("203.0.113.10", username))
                    .doesNotThrowAnyException();
        }

        assertThatThrownBy(() -> limiter.checkLoginAttempt("203.0.113.10", "user-4"))
                .isInstanceOf(RateLimitedException.class)
                .hasMessage("登录尝试过于频繁,请稍后再试");
        // A different source IP is unaffected by another IP's budget.
        assertThatCode(() -> limiter.checkLoginAttempt("203.0.113.11", "user-4"))
                .doesNotThrowAnyException();
    }

    @Test
    void blocksPerAccountAcrossRotatingSourceIps() {
        LoginRateLimiter limiter = limiter(100, 3);
        for (int attempt = 1; attempt <= 3; attempt++) {
            String ip = "203.0.113." + attempt;
            assertThatCode(() -> limiter.checkLoginAttempt(ip, "victim")).doesNotThrowAnyException();
        }

        assertThatThrownBy(() -> limiter.checkLoginAttempt("203.0.113.99", "victim"))
                .isInstanceOf(RateLimitedException.class);
        // Account keys are case-insensitive so casing cannot reset the budget.
        assertThatThrownBy(() -> limiter.checkLoginAttempt("203.0.113.98", "VICTIM"))
                .isInstanceOf(RateLimitedException.class);
        assertThatCode(() -> limiter.checkLoginAttempt("203.0.113.97", "other-account"))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectionCarriesRetryAfterAndIdenticalMessageForKnownAndUnknownAccounts() {
        LoginRateLimiter limiter = limiter(1, 100);
        limiter.checkLoginAttempt("203.0.113.10", "known-account");

        RateLimitedException known = catchRateLimited(limiter, "203.0.113.10", "known-account");
        RateLimitedException unknown = catchRateLimited(limiter, "203.0.113.10", "does-not-exist");

        assertThat(known.getRetryAfterSeconds()).isBetween(1L, 300L);
        assertThat(unknown.getMessage()).isEqualTo(known.getMessage());
        assertThat(unknown.getRetryAfterSeconds()).isBetween(1L, 300L);
    }

    @Test
    void successClearsAccountBudgetButKeepsSourceIpBudget() {
        LoginRateLimiter limiter = limiter(3, 2);
        limiter.checkLoginAttempt("203.0.113.10", "alice");
        limiter.checkLoginAttempt("203.0.113.10", "alice");
        limiter.recordSuccess("alice");

        // Account counter reset, so the next attempt is allowed and consumes the third IP slot.
        assertThatCode(() -> limiter.checkLoginAttempt("203.0.113.10", "alice"))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> limiter.checkLoginAttempt("203.0.113.10", "bob"))
                .isInstanceOf(RateLimitedException.class);
    }

    @Test
    void disabledConfigurationSkipsThrottling() {
        AuthProperties properties = new AuthProperties();
        properties.getLoginRateLimit().setEnabled(false);
        properties.getLoginRateLimit().setPerIp(1);
        properties.getLoginRateLimit().setPerAccount(1);
        LoginRateLimiter limiter = new LoginRateLimiter(properties);

        for (int attempt = 0; attempt < 10; attempt++) {
            assertThatCode(() -> limiter.checkLoginAttempt("203.0.113.10", "alice"))
                    .doesNotThrowAnyException();
        }
    }

    private RateLimitedException catchRateLimited(LoginRateLimiter limiter, String ip, String username) {
        try {
            limiter.checkLoginAttempt(ip, username);
            throw new AssertionError("expected the attempt to be rate limited");
        } catch (RateLimitedException exception) {
            return exception;
        }
    }

    private LoginRateLimiter limiter(int perIp, int perAccount) {
        AuthProperties properties = new AuthProperties();
        properties.getLoginRateLimit().setPerIp(perIp);
        properties.getLoginRateLimit().setPerAccount(perAccount);
        properties.getLoginRateLimit().setWindowSeconds(300);
        return new LoginRateLimiter(properties);
    }
}
