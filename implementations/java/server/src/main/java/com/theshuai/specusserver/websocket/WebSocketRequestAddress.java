package com.theshuai.specusserver.websocket;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.util.StringUtils;

public final class WebSocketRequestAddress {
    /** 无法解析客户端地址时的兜底值;互传"同网"判定显式排除该值,避免无地址客户端被聚为一组。 */
    public static final String UNKNOWN = "unknown";

    public static String resolve(ServerHttpRequest request) {
        if (request instanceof ServletServerHttpRequest servletRequest) {
            return resolve(servletRequest.getServletRequest());
        }
        return request.getRemoteAddress() == null
                ? UNKNOWN
                : request.getRemoteAddress().getAddress().getHostAddress();
    }

    public static String resolve(HttpServletRequest request) {
        String realIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(realIp)) {
            return realIp.trim();
        }
        String forwarded = lastForwarded(request.getHeader("X-Forwarded-For"));
        if (StringUtils.hasText(forwarded)) {
            return forwarded;
        }
        return StringUtils.hasText(request.getRemoteAddr()) ? request.getRemoteAddr().trim() : UNKNOWN;
    }

    private static String lastForwarded(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String[] parts = value.split(",");
        return parts.length == 0 ? "" : parts[parts.length - 1].trim();
    }

    private WebSocketRequestAddress() { }
}
