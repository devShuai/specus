package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.ClientPackageProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientPackageRateLimiterTests {
    @Test
    void limitsEachSourceIndependentlyAndFailsClosedForUnknownSource() {
        ClientPackageProperties properties = new ClientPackageProperties();
        properties.setPublicRateLimitPerIp(2);
        properties.setPublicRateLimitWindowSeconds(60);
        ClientPackageRateLimiter limiter = new ClientPackageRateLimiter(properties);

        limiter.check("192.0.2.1");
        limiter.check("192.0.2.1");
        limiter.check("192.0.2.2");
        assertThatThrownBy(() -> limiter.check("192.0.2.1"))
                .isInstanceOf(RateLimitedException.class)
                .satisfies(exception -> org.assertj.core.api.Assertions.assertThat(
                        ((RateLimitedException) exception).getRetryAfterSeconds()).isPositive());

        limiter.check(null);
        limiter.check("");
        assertThatThrownBy(() -> limiter.check("unknown"))
                .isInstanceOf(RateLimitedException.class);
    }
}
