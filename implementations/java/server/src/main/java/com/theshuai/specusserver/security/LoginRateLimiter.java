package com.theshuai.specusserver.security;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.service.RateLimitedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录尝试限流。与验证码相互独立:关闭 Turnstile 的部署也能约束凭据爆破。
 *
 * <p>同时按来源 IP 和目标账号两个维度做固定窗口计数。账号维度让攻击者换 IP 也无法无限尝试同一个
 * 账号;IP 维度让攻击者换账号也无法无限尝试。两个维度共用同一条 429 文案与 {@code Retry-After},
 * 因此响应不泄露账号是否存在。登录成功会清掉该账号的计数,正常用户不会被自己的历史尝试拖累。
 */
@Slf4j
@Component
public class LoginRateLimiter {
    /** 计数表规模上限,防异常来源撑爆内存;超过则拒绝新来源(现有条目仍受窗口清理)。 */
    private static final int MAX_TRACKED_KEYS = 100_000;
    private static final String RATE_LIMITED_MESSAGE = "登录尝试过于频繁,请稍后再试";

    private final AuthProperties authProperties;
    private final Map<String, Window> ipWindows = new ConcurrentHashMap<>();
    private final Map<String, Window> accountWindows = new ConcurrentHashMap<>();

    public LoginRateLimiter(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    /**
     * 记录一次登录尝试并在超限时抛出 {@link RateLimitedException}。两个维度都会计数,任一超限即拒绝。
     */
    public void checkLoginAttempt(String clientIp, String username) {
        AuthProperties.LoginRateLimit config = authProperties.getLoginRateLimit();
        if (!config.isEnabled()) {
            return;
        }
        long windowSeconds = Math.max(1L, config.getWindowSeconds());
        long now = Instant.now().getEpochSecond();
        // 两个维度都要计数后再判定,避免先超限的维度短路掉另一维度的计数。
        Window ipWindow = record(ipWindows, ipKey(clientIp), now, windowSeconds);
        Window accountWindow = record(accountWindows, accountKey(username), now, windowSeconds);

        boolean ipExceeded = exceeded(ipWindow, config.getPerIp());
        boolean accountExceeded = exceeded(accountWindow, config.getPerAccount());
        if (!ipExceeded && !accountExceeded) {
            return;
        }
        Window blocking = ipExceeded ? ipWindow : accountWindow;
        long retryAfter = retryAfterSeconds(blocking, now, windowSeconds);
        log.warn("[login-rate-limit] 拒绝登录尝试: ip={}, dimension={}, retryAfter={}s",
                ipKey(clientIp), ipExceeded ? "ip" : "account", retryAfter);
        throw new RateLimitedException(RATE_LIMITED_MESSAGE, retryAfter);
    }

    /** 登录成功后清除该账号维度计数;IP 维度保留,避免攻破一个账号后放开整段来源。 */
    public void recordSuccess(String username) {
        accountWindows.remove(accountKey(username));
    }

    @Scheduled(fixedDelay = 600_000L)
    public void purgeExpired() {
        long windowSeconds = Math.max(1L, authProperties.getLoginRateLimit().getWindowSeconds());
        long now = Instant.now().getEpochSecond();
        purge(ipWindows, windowSeconds, now);
        purge(accountWindows, windowSeconds, now);
    }

    private Window record(Map<String, Window> windows, String key, long now, long windowSeconds) {
        if (windows.size() >= MAX_TRACKED_KEYS && !windows.containsKey(key)) {
            // 表已满且是新来源:按超限处理,不再新增条目。
            return new Window(now, Integer.MAX_VALUE);
        }
        return windows.compute(key, (ignored, existing) -> {
            if (existing == null || now - existing.startEpochSeconds >= windowSeconds) {
                return new Window(now, 1);
            }
            existing.count += 1;
            return existing;
        });
    }

    private boolean exceeded(Window window, int configuredLimit) {
        return window.count > Math.max(1, configuredLimit);
    }

    private long retryAfterSeconds(Window window, long now, long windowSeconds) {
        long elapsed = now - window.startEpochSeconds;
        return Math.max(1L, windowSeconds - Math.max(0L, elapsed));
    }

    private String ipKey(String clientIp) {
        return StringUtils.hasText(clientIp) ? clientIp.trim() : "unknown";
    }

    private String accountKey(String username) {
        return StringUtils.hasText(username)
                ? username.trim().toLowerCase(Locale.ROOT)
                : "unknown";
    }

    private void purge(Map<String, Window> windows, long windowSeconds, long now) {
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
