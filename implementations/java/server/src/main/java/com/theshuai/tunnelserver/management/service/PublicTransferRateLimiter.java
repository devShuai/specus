package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.config.PublicTransferProperties;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 免登录 presign-upload 的进程内固定窗口限流:按来源 IP 计数,超过窗口内上限即抛 {@link RateLimitedException}。
 *
 * <p>固定窗口实现简单、内存可控;窗口边界处存在两倍突发的理论上限,对滥用缓解场景可接受。
 * 多实例部署时限额按实例数放大,精确全局限流需外置(如 Redis)。
 */
@Component
public class PublicTransferRateLimiter {
    /** 计数表规模上限,防异常来源撑爆内存;超过则拒绝新来源(现有条目仍受窗口清理)。 */
    private static final int MAX_TRACKED_SOURCES = 100_000;

    private final PublicTransferProperties properties;
    private final Map<String, Window> presignWindows = new ConcurrentHashMap<>();
    private final Map<String, Window> pairingRedeemWindows = new ConcurrentHashMap<>();

    public PublicTransferRateLimiter(PublicTransferProperties properties) {
        this.properties = properties;
    }

    /** 校验来源 IP 是否可再发起一次 presign-upload;超限抛 {@link RateLimitedException}。 */
    public void checkPresignUpload(String clientIp) {
        check(clientIp, presignWindows,
                properties.getPresignRateLimitPerIp(),
                properties.getPresignRateLimitWindowSeconds());
    }

    /** 校验来源 IP 是否可尝试兑换八位配对码。此计数与 OSS presign 限流互不影响。 */
    public void checkPairingCodeRedeem(String clientIp) {
        check(clientIp, pairingRedeemWindows,
                properties.getPairingCodeRedeemRateLimitPerIp(),
                properties.getPairingCodeRedeemRateLimitWindowSeconds());
    }

    /** 定期清理过期窗口,避免长期累积。 */
    @Scheduled(fixedDelay = 600_000L)
    public void purgeExpired() {
        long now = Instant.now().getEpochSecond();
        purge(presignWindows, properties.getPresignRateLimitWindowSeconds(), now);
        purge(pairingRedeemWindows, properties.getPairingCodeRedeemRateLimitWindowSeconds(), now);
    }

    private void check(String clientIp, Map<String, Window> windows, int configuredLimit, long configuredWindowSeconds) {
        String key = StringUtils.hasText(clientIp) ? clientIp.trim() : "unknown";
        int limit = Math.max(1, configuredLimit);
        long windowSeconds = Math.max(1L, configuredWindowSeconds);
        long now = Instant.now().getEpochSecond();

        if (windows.size() >= MAX_TRACKED_SOURCES && !windows.containsKey(key)) {
            throw new RateLimitedException("请求过于频繁,请稍后再试");
        }

        Window window = windows.compute(key, (ignored, existing) -> {
            if (existing == null || now - existing.startEpochSeconds >= windowSeconds) {
                return new Window(now, 1);
            }
            existing.count += 1;
            return existing;
        });

        if (window.count > limit) {
            throw new RateLimitedException("请求过于频繁,请稍后再试");
        }
    }

    private void purge(Map<String, Window> windows, long configuredWindowSeconds, long now) {
        long windowSeconds = Math.max(1L, configuredWindowSeconds);
        windows.entrySet().removeIf(entry -> now - entry.getValue().startEpochSeconds >= windowSeconds);
    }

    private static final class Window {
        private final long startEpochSeconds;
        private int count;

        private Window(long startEpochSeconds, int count) {
            this.startEpochSeconds = startEpochSeconds;
            this.count = count;
        }
    }
}
