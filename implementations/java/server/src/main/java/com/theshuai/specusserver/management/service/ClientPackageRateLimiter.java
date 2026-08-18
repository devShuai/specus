package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.ClientPackageProperties;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Bounded per-IP fixed-window limiter for every anonymous client-package read endpoint. */
@Component
public class ClientPackageRateLimiter {
    private static final int MAX_TRACKED_SOURCES = 100_000;

    private final ClientPackageProperties properties;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public ClientPackageRateLimiter(ClientPackageProperties properties) {
        this.properties = properties;
    }

    public void check(String clientIp) {
        String key = StringUtils.hasText(clientIp) ? clientIp.trim() : "unknown";
        int limit = Math.max(1, properties.getPublicRateLimitPerIp());
        long windowSeconds = Math.max(1L, properties.getPublicRateLimitWindowSeconds());
        long now = Instant.now().getEpochSecond();
        if (windows.size() >= MAX_TRACKED_SOURCES && !windows.containsKey(key)) {
            throw new RateLimitedException("请求过于频繁,请稍后再试", windowSeconds);
        }
        Window window = windows.compute(key, (ignored, existing) -> {
            if (existing == null || now - existing.startedAt >= windowSeconds) {
                return new Window(now, 1);
            }
            existing.count++;
            return existing;
        });
        if (window.count > limit) {
            long retryAfter = Math.max(1L, windowSeconds - Math.max(0L, now - window.startedAt));
            throw new RateLimitedException("请求过于频繁,请稍后再试", retryAfter);
        }
    }

    @Scheduled(fixedDelay = 600_000L)
    public void purgeExpired() {
        long now = Instant.now().getEpochSecond();
        long windowSeconds = Math.max(1L, properties.getPublicRateLimitWindowSeconds());
        windows.entrySet().removeIf(entry -> now - entry.getValue().startedAt >= windowSeconds);
    }

    private static final class Window {
        private final long startedAt;
        private int count;

        private Window(long startedAt, int count) {
            this.startedAt = startedAt;
            this.count = count;
        }
    }
}
