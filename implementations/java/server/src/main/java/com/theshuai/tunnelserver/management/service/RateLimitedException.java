package com.theshuai.tunnelserver.management.service;

/**
 * 请求触发滥用防护限制(来源 IP 限流或房间配额)时抛出,由 GlobalExceptionHandler 映射为 HTTP 429。
 */
public class RateLimitedException extends RuntimeException {
    public RateLimitedException(String message) {
        super(message);
    }
}
