package com.theshuai.tunnelserver.websocket;

import com.theshuai.tunnelserver.management.tenant.TenantResolver;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Map;

/**
 * 在 WebSocket 升级握手阶段验证 JWT。浏览器原生 {@code WebSocket} 构造器不能塞 Authorization
 * 头，因此 token 通过查询串 {@code ?token=...} 携带，由这里解码（{@link JwtDecoder} 已支持
 * HS256 本地 token 与 OIDC RS256 token 路由）。
 *
 * <p>失败时回 403，与 Spring Security 在 REST API 上的 401 区分：
 * 浏览器拿不到响应体，前端只能看到 close code，约定 4401 表示鉴权失败需要重新登录。
 */
public class JwtHandshakeInterceptor implements HandshakeInterceptor {
    private static final Logger log = LoggerFactory.getLogger(JwtHandshakeInterceptor.class);

    /** 握手成功后塞进 WebSocketSession attributes 的 key，handler 内可读取调试用。 */
    public static final String ATTR_USER = "wsUser";
    public static final String ATTR_TENANT_ID = "tenantId";

    private final JwtDecoder jwtDecoder;
    private final TenantResolver tenantResolver;

    public JwtHandshakeInterceptor(JwtDecoder jwtDecoder, TenantResolver tenantResolver) {
        this.jwtDecoder = jwtDecoder;
        this.tenantResolver = tenantResolver;
    }

    @Override
    public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                   WebSocketHandler wsHandler, Map<String, Object> attributes) {
        String token = extractToken(request);
        if (token == null) {
            return reject(response, "missing token");
        }
        try {
            Jwt jwt = jwtDecoder.decode(token);
            attributes.put(ATTR_USER, jwt.getSubject());
            attributes.put(ATTR_TENANT_ID, tenantResolver.resolve(jwt).tenantId());
            return true;
        } catch (JwtException e) {
            log.debug("ws handshake JWT rejected: {}", e.getMessage());
            return reject(response, "invalid token");
        }
    }

    @Override
    public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response,
                               WebSocketHandler wsHandler, Exception exception) {
        // no-op
    }

    /** 优先取查询参数 {@code token}；兜底支持 {@code Authorization: Bearer xxx} 头（非浏览器客户端用）。 */
    private static String extractToken(ServerHttpRequest request) {
        List<String> tokens = UriComponentsBuilder.fromUri(request.getURI())
                .build()
                .getQueryParams()
                .get("token");
        if (tokens != null && !tokens.isEmpty()) {
            String t = tokens.get(0);
            if (t != null && !t.isBlank()) {
                return t;
            }
        }
        List<String> authHeaders = request.getHeaders().get("Authorization");
        if (authHeaders != null) {
            for (String h : authHeaders) {
                if (h != null && h.startsWith("Bearer ")) {
                    String t = h.substring("Bearer ".length()).trim();
                    if (!t.isEmpty()) {
                        return t;
                    }
                }
            }
        }
        return null;
    }

    private static boolean reject(ServerHttpResponse response, String reason) {
        if (response instanceof ServletServerHttpResponse servletResp) {
            HttpServletResponse raw = servletResp.getServletResponse();
            raw.setStatus(HttpServletResponse.SC_FORBIDDEN);
            // 让浏览器 onclose 拿到的 wasClean=false、code=1006，前端按 4401 close 通道走 reauth。
            // 这里同时打个简单原因头便于排查。
            raw.setHeader("X-Auth-Reason", reason);
        }
        return false;
    }

    @SuppressWarnings("unused")
    private static ServletServerHttpRequest asServlet(ServerHttpRequest request) {
        return (ServletServerHttpRequest) request;
    }
}
