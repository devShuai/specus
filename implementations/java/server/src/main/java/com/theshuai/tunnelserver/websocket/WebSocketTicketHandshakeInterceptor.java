package com.theshuai.tunnelserver.websocket;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Map;

public final class WebSocketTicketHandshakeInterceptor implements HandshakeInterceptor {
    public static final String ATTR_USER = "wsUser";
    public static final String ATTR_TENANT_ID = "tenantId";
    public static final String ATTR_ADMIN = "admin";

    private final WebSocketTicketService ticketService;
    private final WebSocketTicketService.Scope scope;
    private final boolean bindRemoteAddress;

    public WebSocketTicketHandshakeInterceptor(WebSocketTicketService ticketService,
                                               WebSocketTicketService.Scope scope,
                                               boolean bindRemoteAddress) {
        this.ticketService = ticketService;
        this.scope = scope;
        this.bindRemoteAddress = bindRemoteAddress;
    }

    @Override
    public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                   WebSocketHandler wsHandler, Map<String, Object> attributes) {
        Map<String, List<String>> query = UriComponentsBuilder.fromUri(request.getURI())
                .build()
                .getQueryParams();
        List<String> values = query.get("ticket");
        if (query.size() != 1 || values == null || values.size() != 1) {
            return reject(response, "single-use ticket required");
        }
        String remoteAddress = bindRemoteAddress ? WebSocketRequestAddress.resolve(request) : null;
        return ticketService.consume(scope, values.getFirst(), remoteAddress)
                .map(ticketAttributes -> {
                    attributes.putAll(ticketAttributes);
                    return true;
                })
                .orElseGet(() -> reject(response, "invalid or consumed ticket"));
    }

    @Override
    public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response,
                               WebSocketHandler wsHandler, Exception exception) {
        // no-op
    }

    private static boolean reject(ServerHttpResponse response, String reason) {
        if (response instanceof ServletServerHttpResponse servletResponse) {
            HttpServletResponse raw = servletResponse.getServletResponse();
            raw.setStatus(HttpServletResponse.SC_FORBIDDEN);
            raw.setHeader("X-Auth-Reason", reason);
        }
        return false;
    }
}
