package com.theshuai.stunserver;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StunRequestLimiterTests {
    @Test
    void enforcesSourceBurstAndBoundsTrackedSources() throws Exception {
        StandaloneStunProtectionConfig config = new StandaloneStunProtectionConfig(
                1,
                2,
                100,
                100,
                1,
                300,
                65_507,
                1_472);
        StunRequestLimiter limiter = new StunRequestLimiter(config);
        InetAddress first = InetAddress.getByName("198.51.100.1");
        InetAddress second = InetAddress.getByName("198.51.100.2");

        assertEquals(StunRequestLimiter.Decision.ALLOWED, limiter.allow(first));
        assertEquals(StunRequestLimiter.Decision.ALLOWED, limiter.allow(first));
        assertEquals(StunRequestLimiter.Decision.SOURCE_RATE_LIMIT, limiter.allow(first));
        assertEquals(StunRequestLimiter.Decision.SOURCE_TABLE_FULL, limiter.allow(second));
        assertEquals(1, limiter.trackedSources());
    }
}
