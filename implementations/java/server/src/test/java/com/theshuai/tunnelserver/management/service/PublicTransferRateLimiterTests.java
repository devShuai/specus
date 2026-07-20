package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.config.PublicTransferProperties;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PublicTransferRateLimiterTests {

    @Test
    void pairingCodeRedeemHasIndependentTenPerFiveMinuteIpLimit() {
        PublicTransferProperties properties = new PublicTransferProperties();
        properties.setPairingCodeRedeemRateLimitPerIp(10);
        properties.setPairingCodeRedeemRateLimitWindowSeconds(300);
        properties.setPresignRateLimitPerIp(1);
        PublicTransferRateLimiter limiter = new PublicTransferRateLimiter(properties);

        for (int attempt = 0; attempt < 10; attempt++) {
            assertDoesNotThrow(() -> limiter.checkPairingCodeRedeem("203.0.113.8"));
        }
        assertThrows(RateLimitedException.class,
                () -> limiter.checkPairingCodeRedeem("203.0.113.8"));

        // Pairing attempts do not consume the separate OSS presign quota.
        assertDoesNotThrow(() -> limiter.checkPresignUpload("203.0.113.8"));
        assertThrows(RateLimitedException.class,
                () -> limiter.checkPresignUpload("203.0.113.8"));
    }
}
