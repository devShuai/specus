package com.theshuai.specusserver.productmetrics;

import org.springframework.stereotype.Component;

/** Wall clock of the product metrics: day boundaries, the onboarding window, limiter minutes. */
@Component
public class ProductMetricsClock {
    /** Epoch milliseconds now. Tests replace the bean to pin it. */
    public long millis() {
        return System.currentTimeMillis();
    }
}
