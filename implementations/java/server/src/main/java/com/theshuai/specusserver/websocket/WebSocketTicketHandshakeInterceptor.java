package com.theshuai.specusserver.websocket;

import com.theshuai.specusserver.security.ClientAddressResolver;
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
    /** The account key of a management ticket's identity, the {@code uid} of its token; absent for the built-in admin. */
    public static final String ATTR_ACCOUNT_KEY = "uid";

    private final WebSocketTicketService ticketService;
    private final ClientAddressResolver addressResolver;
    private final WebSocketTicketService.Scope scope;
    private final boolean bindRemoteAddress;
    /** Re-resolves a management ticket's identity; {@code null} for tickets that carry none. */
    private final ManagementWebSocketIdentity identity;

    public WebSocketTicketHandshakeInterceptor(WebSocketTicketService ticketService,
                                               ClientAddressResolver addressResolver,
                                               WebSocketTicketService.Scope scope,
                                               boolean bindRemoteAddress) {
        this(ticketService, addressResolver, scope, bindRemoteAddress, null);
    }

    public WebSocketTicketHandshakeInterceptor(WebSocketTicketService ticketService,
                                               ClientAddressResolver addressResolver,
                                               WebSocketTicketService.Scope scope,
                                               boolean bindRemoteAddress,
                                               ManagementWebSocketIdentity identity) {
        this.ticketService = ticketService;
        this.addressResolver = addressResolver;
        this.scope = scope;
        this.bindRemoteAddress = bindRemoteAddress;
        this.identity = identity;
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
        String remoteAddress = bindRemoteAddress
                ? WebSocketRequestAddress.resolve(addressResolver, request)
                : null;
        Map<String, Object> ticketAttributes = ticketService.consume(scope, values.getFirst(), remoteAddress)
                .orElse(null);
        if (ticketAttributes == null) {
            return reject(response, "invalid or consumed ticket");
        }
        // The account may have been deleted, disabled or given another role since the ticket was
        // issued (management-accounts.md 7.2).
        if (identity != null && !identity.current(ticketAttributes)) {
            return reject(response, ManagementWebSocketIdentity.REVOKED);
        }
        attributes.putAll(ticketAttributes);
        return true;
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
