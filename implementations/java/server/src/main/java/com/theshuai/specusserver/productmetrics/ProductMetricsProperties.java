package com.theshuai.specusserver.productmetrics;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Deployment settings of the opt-in product metrics (protocol/spec/product-metrics.md sections 8
 * and 13). {@code allowed=false} keeps every tenant off: enabling answers 409 and nothing is
 * collected. The per-minute event budgets are per process.
 */
@Component
@ConfigurationProperties(prefix = "specus.product-metrics")
@Data
public class ProductMetricsProperties {
    private boolean allowed = true;
    private int perUserEventsPerMinute = ProductMetricsModel.DEFAULT_PER_USER_EVENTS_PER_MINUTE;
    private int perTenantEventsPerMinute = ProductMetricsModel.DEFAULT_PER_TENANT_EVENTS_PER_MINUTE;
}
