package com.theshuai.specusserver.management.service;

import org.springframework.stereotype.Component;

/**
 * The one millisecond clock of the service workbench: favourite and visit times, the retention
 * window, the sweep cutoff and the rate limiter all read it. Production uses system time; tests
 * replace the bean to pin the time of every step.
 */
@Component
public class WorkbenchClock {
    public long millis() {
        return System.currentTimeMillis();
    }
}
