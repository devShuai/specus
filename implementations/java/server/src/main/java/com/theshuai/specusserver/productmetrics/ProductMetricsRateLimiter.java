package com.theshuai.specusserver.productmetrics;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Fixed UTC-minute event budgets per member (tenant + username) and per tenant (section 8). A batch
 * that would exceed either budget is refused whole and charges nothing. Per process, like the other
 * limiters: with several instances the effective budget is a multiple, which only affects the
 * tenant's own statistics.
 */
@Component
public class ProductMetricsRateLimiter {
    private final ProductMetricsProperties properties;
    private long minute = Long.MIN_VALUE;
    private final Map<String, Integer> members = new HashMap<>();
    private final Map<String, Integer> tenants = new HashMap<>();

    public ProductMetricsRateLimiter(ProductMetricsProperties properties) {
        this.properties = properties;
    }

    public synchronized boolean admit(String tenantId, String username, int events, long nowMillis) {
        long current = Math.floorDiv(nowMillis, 60_000L);
        if (current != minute) {
            minute = current;
            members.clear();
            tenants.clear();
        }
        String member = tenantId + "\n" + username;
        int memberUsed = members.getOrDefault(member, 0);
        int tenantUsed = tenants.getOrDefault(tenantId, 0);
        if (memberUsed + events > properties.getPerUserEventsPerMinute()
                || tenantUsed + events > properties.getPerTenantEventsPerMinute()) {
            return false;
        }
        members.put(member, memberUsed + events);
        tenants.put(tenantId, tenantUsed + events);
        return true;
    }

    /** Forgets every window; tests start each scenario from an empty limiter. */
    public synchronized void clear() {
        minute = Long.MIN_VALUE;
        members.clear();
        tenants.clear();
    }
}
