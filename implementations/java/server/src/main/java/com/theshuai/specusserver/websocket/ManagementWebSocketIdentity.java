package com.theshuai.specusserver.websocket;

import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.service.ManagementUserService;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Whether the identity a management WebSocket ticket recorded still holds (management-accounts.md
 * 7.2): it resolves as a token of that login name, tenant and account key would (section 6), and
 * with the same administrator rights. Checked at the handshake and again once the connection is
 * registered, so a revocation racing the handshake cannot leave a connection behind.
 */
@Component
public class ManagementWebSocketIdentity {
    /** The {@code X-Auth-Reason} of a refused handshake and the reason of the 1008 close. */
    public static final String REVOKED = "identity revoked";

    private final ManagementUserService users;

    public ManagementWebSocketIdentity(ManagementUserService users) {
        this.users = users;
    }

    public boolean current(Map<String, Object> attributes) {
        if (!(attributes.get(WebSocketTicketHandshakeInterceptor.ATTR_USER) instanceof String username)
                || !(attributes.get(WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID) instanceof String tenantId)) {
            return false;
        }
        // Tickets issued before the key was recorded resolve like tokens without uid.
        String accountKey = attributes.get(WebSocketTicketHandshakeInterceptor.ATTR_ACCOUNT_KEY) instanceof String key
                ? key
                : null;
        boolean admin = Boolean.TRUE.equals(attributes.get(WebSocketTicketHandshakeInterceptor.ATTR_ADMIN));
        return users.resolveLocalTokenUser(username, tenantId, accountKey)
                .map(user -> (user.role() == ManagementRole.ADMIN) == admin)
                .orElse(false);
    }
}
