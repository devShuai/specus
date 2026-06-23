package com.theshuai.tunnelserver.http;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * WebSocket 隧道握手拦截器：从 {@code /http/{clientName}/{route}/**} 的升级请求里提取
 * clientName / route / relativePath / rawQuery / headers / body，塞进握手 attributes，
 * 供 {@link WebSocketTunnelHandler#afterConnectionEstablished} 组装 {@code CONNECTED} 帧使用。
 *
 * <p>握手阶段还会做最小校验：
 * <ul>
 *   <li>路由路径解析失败（找不到 clientName/route 段）→ 拒绝握手（返回 400）。</li>
 *   <li>请求体读不出来（理论上 GET 升级请求无体）→ 用空 byte[]。</li>
 * </ul>
 *
 * <p>注意：握手拦截器运行在 Spring MVC 同步线程里，{@code beforeHandshake} 读取的 body 在
 * GET 升级请求中通常为空。WS 握手是 GET 请求，按 RFC 6455 不应带 body；这里仍尝试读，
 * 仅为兼容非标准客户端。
 */
@Component
@Slf4j
public class WebSocketTunnelHandshakeInterceptor implements HandshakeInterceptor {
    private static final Set<String> SKIPPED_HEADERS = Set.of(
            "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
            "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions",
            "sec-websocket-protocol", "sec-websocket-accept"
    );

    @Override
    public boolean beforeHandshake(ServerHttpRequest request,
                                   ServerHttpResponse response,
                                   WebSocketHandler wsHandler,
                                   Map<String, Object> attributes) {
        if (!(request instanceof ServletServerHttpRequest servletRequest)) {
            log.warn("[ws-tunnel][handshake] non-servlet request, rejecting");
            return false;
        }
        HttpServletRequest http = servletRequest.getServletRequest();
        PathParts parts = parsePath(http.getRequestURI(), http.getContextPath());
        if (parts == null) {
            log.warn("[ws-tunnel][handshake] malformed path: {}", http.getRequestURI());
            return false;
        }
        attributes.put(WebSocketTunnelHandler.ATTR_CLIENT_NAME, parts.clientName);
        attributes.put(WebSocketTunnelHandler.ATTR_ROUTE, parts.route);
        attributes.put(WebSocketTunnelHandler.ATTR_RELATIVE_PATH, parts.relativePath);
        attributes.put(WebSocketTunnelHandler.ATTR_RAW_QUERY, http.getQueryString());
        attributes.put(WebSocketTunnelHandler.ATTR_HEADERS, collectHeaders(http));
        // WS 升级是 GET，无 body；保留空数组占位，保持 CONNECTED metaData 结构一致
        attributes.put(WebSocketTunnelHandler.ATTR_BODY, new byte[0]);
        return true;
    }

    @Override
    public void afterHandshake(ServerHttpRequest request,
                               ServerHttpResponse response,
                               WebSocketHandler wsHandler,
                               Exception exception) {
        // no-op
    }

    static PathParts parsePath(String requestUri, String contextPath) {
        String path = requestUri;
        // 去掉 contextPath 前缀（通常为空）
        if (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }
        int httpPrefix = path.indexOf('/', 0); // 跳过第一个 '/'
        if (httpPrefix != 0 || path.length() < "/http/".length()) {
            return null;
        }
        // path 形如 /http/{clientName}/{route}/...
        int clientStart = "/http/".length();
        int clientEnd = path.indexOf('/', clientStart);
        if (clientEnd < 0) {
            return null;
        }
        String clientName = path.substring(clientStart, clientEnd);
        int routeEnd = path.indexOf('/', clientEnd + 1);
        String route;
        String relativePath;
        if (routeEnd < 0) {
            route = path.substring(clientEnd + 1);
            relativePath = "/";
        } else {
            route = path.substring(clientEnd + 1, routeEnd);
            relativePath = path.substring(routeEnd);
        }
        if (clientName.isEmpty() || route.isEmpty()) {
            return null;
        }
        return new PathParts(clientName, route, relativePath);
    }

    private static List<String> collectHeaders(HttpServletRequest request) {
        List<String> headers = new ArrayList<>();
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            if (!shouldForward(name)) {
                continue;
            }
            Enumeration<String> values = request.getHeaders(name);
            while (values.hasMoreElements()) {
                headers.add(name + ":" + values.nextElement());
            }
        }
        return headers;
    }

    private static boolean shouldForward(String name) {
        return name != null && !SKIPPED_HEADERS.contains(name.toLowerCase(Locale.ROOT));
    }

    record PathParts(String clientName, String route, String relativePath) {
    }
}
