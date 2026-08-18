package com.theshuai.specusserver.websocket;

import com.theshuai.specusserver.security.ClientAddressResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServletServerHttpRequest;

/**
 * WebSocket 握手侧的地址解析门面。真正的判定逻辑集中在 {@link ClientAddressResolver}，这里只负责把
 * Spring 的两种请求表示适配过去，保证 WS 与 REST 入口使用同一套可信代理边界。
 */
public final class WebSocketRequestAddress {
    /** 无法解析客户端地址时的兜底值;互传"同网"判定显式排除该值,避免无地址客户端被聚为一组。 */
    public static final String UNKNOWN = ClientAddressResolver.UNKNOWN;

    public static String resolve(ClientAddressResolver resolver, ServerHttpRequest request) {
        if (request instanceof ServletServerHttpRequest servletRequest) {
            return resolve(resolver, servletRequest.getServletRequest());
        }
        if (request == null || request.getRemoteAddress() == null) {
            return UNKNOWN;
        }
        // 非 Servlet 握手没有可用的 header 视图，只能使用连接对端地址。
        return resolver.resolve(
                request.getRemoteAddress().getAddress().getHostAddress(), null, null);
    }

    public static String resolve(ClientAddressResolver resolver, HttpServletRequest request) {
        return resolver.resolve(request);
    }

    private WebSocketRequestAddress() { }
}
