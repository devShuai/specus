package com.theshuai.specusserver.security;

import com.theshuai.specusserver.config.TrustedProxyProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 唯一的真实客户端地址解析入口，供限流、配对、上传、WebSocket ticket 和互传同网判定复用。
 *
 * <p>转发头只有在连接对端属于已配置的可信代理 CIDR 时才被采纳。未配置可信代理（默认）时完全忽略
 * {@code X-Forwarded-For} / {@code X-Real-IP}，直连客户端因此无法通过伪造头部改写自己的来源地址。
 *
 * <p>可信来源的 {@code X-Forwarded-For} 按代理链从右向左解析：跳过链尾连续的可信代理，第一个非可信
 * 地址即真实客户端。非法地址一律丢弃，不参与判定。
 */
@Slf4j
@Component
public class ClientAddressResolver {
    /** 无法解析客户端地址时的兜底值；互传"同网"判定显式排除该值。 */
    public static final String UNKNOWN = "unknown";

    private final List<CidrRange> trustedProxies;

    public ClientAddressResolver(TrustedProxyProperties properties) {
        this.trustedProxies = parseRanges(properties.getTrustedProxies());
        if (!this.trustedProxies.isEmpty()) {
            log.info("[trusted-proxy] 已启用转发头解析: {} 个可信网段", this.trustedProxies.size());
        }
    }

    public String resolve(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN;
        }
        String peer = normalize(request.getRemoteAddr());
        if (!isTrustedProxy(peer)) {
            // 非可信来源：转发头完全不参与判定。
            return StringUtils.hasText(peer) ? peer : UNKNOWN;
        }
        String forwarded = resolveForwarded(
                request.getHeader("X-Forwarded-For"), request.getHeader("X-Real-IP"));
        if (StringUtils.hasText(forwarded)) {
            return forwarded;
        }
        return StringUtils.hasText(peer) ? peer : UNKNOWN;
    }

    /** 供已持有头部值的调用方（如 WebSocket 握手）复用同一套判定。 */
    public String resolve(String remoteAddress, String forwardedForHeader, String realIpHeader) {
        String peer = normalize(remoteAddress);
        if (!isTrustedProxy(peer)) {
            return StringUtils.hasText(peer) ? peer : UNKNOWN;
        }
        String forwarded = resolveForwarded(forwardedForHeader, realIpHeader);
        if (StringUtils.hasText(forwarded)) {
            return forwarded;
        }
        return StringUtils.hasText(peer) ? peer : UNKNOWN;
    }

    private String resolveForwarded(String forwardedForHeader, String realIpHeader) {
        // X-Forwarded-For 更完整：先按代理链从右向左找出第一个非可信地址。
        if (StringUtils.hasText(forwardedForHeader)) {
            String[] hops = forwardedForHeader.split(",");
            for (int index = hops.length - 1; index >= 0; index--) {
                String candidate = normalize(hops[index]);
                if (!StringUtils.hasText(candidate) || !isValidAddress(candidate)) {
                    continue;
                }
                if (!isTrustedProxy(candidate)) {
                    return candidate;
                }
            }
        }
        // 链上全是可信代理或没有 XFF 时，退回代理显式覆写的单值头。
        String realIp = normalize(realIpHeader);
        return isValidAddress(realIp) ? realIp : "";
    }

    private boolean isTrustedProxy(String address) {
        if (trustedProxies.isEmpty() || !StringUtils.hasText(address)) {
            return false;
        }
        byte[] candidate = toBytes(address);
        if (candidate == null) {
            return false;
        }
        return trustedProxies.stream().anyMatch(range -> range.contains(candidate));
    }

    private static boolean isValidAddress(String value) {
        return StringUtils.hasText(value) && toBytes(value) != null;
    }

    private static String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String trimmed = value.trim();
        // IPv6 字面量可能带方括号；scope id（fe80::1%eth0）对地址判定无意义。
        if (trimmed.startsWith("[")) {
            int end = trimmed.indexOf(']');
            if (end > 0) {
                trimmed = trimmed.substring(1, end);
            }
        }
        int scope = trimmed.indexOf('%');
        return scope > 0 ? trimmed.substring(0, scope) : trimmed;
    }

    private static byte[] toBytes(String address) {
        if (!StringUtils.hasText(address)) {
            return null;
        }
        // 只接受字面量地址：绝不因解析来源地址触发 DNS。
        if (address.chars().anyMatch(Character::isLetter) && address.indexOf(':') < 0) {
            return null;
        }
        try {
            return InetAddress.getByName(address).getAddress();
        } catch (UnknownHostException | SecurityException e) {
            return null;
        }
    }

    private static List<CidrRange> parseRanges(List<String> values) {
        List<CidrRange> ranges = new ArrayList<>();
        if (values == null) {
            return ranges;
        }
        for (String value : values) {
            CidrRange range = CidrRange.parse(value);
            if (range == null) {
                if (StringUtils.hasText(value)) {
                    log.warn("[trusted-proxy] 忽略无效的可信代理网段: {}", value);
                }
                continue;
            }
            ranges.add(range);
        }
        return ranges;
    }

    private record CidrRange(byte[] network, int prefixLength) {
        static CidrRange parse(String value) {
            if (!StringUtils.hasText(value)) {
                return null;
            }
            String trimmed = value.trim();
            int slash = trimmed.indexOf('/');
            String host = slash < 0 ? trimmed : trimmed.substring(0, slash);
            byte[] network = toBytes(normalize(host));
            if (network == null) {
                return null;
            }
            int maxPrefix = network.length * 8;
            if (slash < 0) {
                return new CidrRange(network, maxPrefix);
            }
            try {
                int prefix = Integer.parseInt(trimmed.substring(slash + 1).trim());
                if (prefix < 0 || prefix > maxPrefix) {
                    return null;
                }
                return new CidrRange(network, prefix);
            } catch (NumberFormatException e) {
                return null;
            }
        }

        boolean contains(byte[] candidate) {
            if (candidate.length != network.length) {
                // IPv4 与 IPv6 不跨族比较；IPv4-mapped IPv6 由 InetAddress 归一化为 4 字节。
                return false;
            }
            int fullBytes = prefixLength / 8;
            for (int index = 0; index < fullBytes; index++) {
                if (candidate[index] != network[index]) {
                    return false;
                }
            }
            int remainingBits = prefixLength % 8;
            if (remainingBits == 0) {
                return true;
            }
            int mask = 0xFF << (8 - remainingBits);
            return (candidate[fullBytes] & mask) == (network[fullBytes] & mask);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof CidrRange range
                    && prefixLength == range.prefixLength
                    && Arrays.equals(network, range.network);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(network) * 31 + prefixLength;
        }

        @Override
        public String toString() {
            return Arrays.toString(network) + "/" + prefixLength;
        }
    }
}
