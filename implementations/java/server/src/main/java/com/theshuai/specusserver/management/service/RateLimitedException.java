package com.theshuai.specusserver.management.service;

/**
 * 请求触发滥用防护限制(来源 IP 限流或房间配额)时抛出,由 GlobalExceptionHandler 映射为 HTTP 429。
 *
 * <p>{@code retryAfterSeconds} 大于 0 时会作为 {@code Retry-After} 响应头返回。
 */
public class RateLimitedException extends RuntimeException {
    private final long retryAfterSeconds;

    public RateLimitedException(String message) {
        this(message, 0L);
    }

    public RateLimitedException(String message, long retryAfterSeconds) {
        super(message);
        this.retryAfterSeconds = Math.max(0L, retryAfterSeconds);
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
