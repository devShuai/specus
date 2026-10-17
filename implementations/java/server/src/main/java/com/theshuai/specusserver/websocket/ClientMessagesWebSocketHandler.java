package com.theshuai.specusserver.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.ManagementMessageRelayService;
import com.theshuai.specusserver.management.service.ManagementMessageAuthority;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class ClientMessagesWebSocketHandler extends TextWebSocketHandler {
    private static final int MAX_MESSAGE_CHARS = 64 * 1024;

    private final ObjectMapper objectMapper = new ObjectMapper()
            .setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
    private final ClientAccountService clientAccountService;
    private final ManagementMessageRelayService relay;
    private final Map<String, Set<WebSocketSession>> adminSessions = new ConcurrentHashMap<>();
    /** Fast handshake check; the publisher also locks and revalidates identity for every message. */
    private final ManagementWebSocketIdentity identity;

    public ClientMessagesWebSocketHandler(ClientAccountService clientAccountService,
                                          ManagementMessageRelayService relay,
                                          ManagementWebSocketIdentity identity) {
        this.clientAccountService = clientAccountService;
        this.relay = relay;
        this.identity = identity;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        // Keep the container aggregation limit aligned with the explicit 64K character guard.
        // Tomcat/Spring otherwise defaults to a much smaller text-message buffer.
        session.setTextMessageSizeLimit(MAX_MESSAGE_CHARS);
        session.setBinaryMessageSizeLimit(MAX_MESSAGE_CHARS);
        var resolved = identity.resolve(session.getAttributes()).orElse(null);
        if (resolved == null) {
            session.close(CloseStatus.POLICY_VIOLATION.withReason(ManagementWebSocketIdentity.REVOKED));
            return;
        }
        // Canonicalize and pin legacy UID-less tickets once, before registration. Never resolve
        // this connection again by a reusable login name at message publication time.
        var attributes = session.getAttributes();
        attributes.put(WebSocketTicketHandshakeInterceptor.ATTR_USER, resolved.username());
        attributes.put(WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID, resolved.tenant().tenantId());
        attributes.put(WebSocketTicketHandshakeInterceptor.ATTR_ADMIN, resolved.isAdmin());
        if (resolved.accountKey() == null) attributes.remove(WebSocketTicketHandshakeInterceptor.ATTR_ACCOUNT_KEY);
        else attributes.put(WebSocketTicketHandshakeInterceptor.ATTR_ACCOUNT_KEY, resolved.accountKey());
        adminSessions.computeIfAbsent(adminSessionKey(session), ignored -> ConcurrentHashMap.newKeySet()).add(session);
        // Registered first, checked second: a revocation that committed before this check is seen
        // here, one that commits after it finds the session (management-accounts.md 7.2).
        if (!identity.current(session.getAttributes())) {
            unregister(session);
            session.close(CloseStatus.POLICY_VIOLATION.withReason(ManagementWebSocketIdentity.REVOKED));
            return;
        }
        send(session, Map.of(
                "type", "hello",
                "channel", "client-messages",
                "username", attr(session, WebSocketTicketHandshakeInterceptor.ATTR_USER),
                "tenantId", attr(session, WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID)));
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        unregister(session);
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        unregister(session);
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        if (message.getPayloadLength() > MAX_MESSAGE_CHARS) {
            session.close(CloseStatus.TOO_BIG_TO_PROCESS);
            return;
        }
        ClientMessageCommand command;
        try {
            command = objectMapper.readValue(message.getPayload(), ClientMessageCommand.class);
        } catch (Exception e) {
            send(session, Map.of("type", "error", "error", "invalid-json"));
            return;
        }
        if (!"message".equals(command.type())) {
            sendError(session, "unsupported-type", command);
            return;
        }
        String toClientName = command.toClientName() == null ? "" : command.toClientName().trim();
        String body = command.message() == null ? "" : command.message().trim();
        if (toClientName.isBlank() || body.isBlank()) {
            sendError(session, "target-and-message-required", command);
            return;
        }

        ClientAccount target = clientAccountService.findClientByName(toClientName).orElse(null);
        if (target == null) {
            sendError(session, "target-not-found", command);
            return;
        }
        try { relay.toClient(session, target, body, command.messageId()); }
        catch (ManagementMessageAuthority.Denied revoked) {
            unregister(session); session.close(CloseStatus.POLICY_VIOLATION.withReason(ManagementWebSocketIdentity.REVOKED));
        } catch (IllegalArgumentException invalid) { sendError(session, "message-too-large", command); }
        catch (IllegalStateException busy) { sendError(session, "server-busy", command); }
    }

    /** Returns queue acceptance, not a delivery acknowledgement. The actual receiving identity
     * and current resource ownership are checked independently at publication for each tab. */
    public boolean deliverFromClient(ClientAccount source, String targetAdminName, String body, Channel incoming) {
        String username = normalizeAdminTarget(targetAdminName);
        if (source == null || username.isBlank() || body == null || body.isBlank()) {
            return false;
        }
        Set<WebSocketSession> sessions = adminSessions.get(adminSessionKey(source.getTenantId(), username));
        if (sessions == null || sessions.isEmpty()) {
            return false;
        }
        boolean delivered = false;
        for (WebSocketSession session : sessions) {
            if (!session.isOpen()) {
                sessions.remove(session);
                continue;
            }
            try {
                relay.fromClient(session, source, incoming, body);
                delivered = true;
            } catch (Exception e) {
                log.warn("client-message websocket delivery failed: source={}, admin={}, reason={}",
                        source.getClientName(), username, e.getMessage());
            }
        }
        return delivered;
    }

    /**
     * The account of this identity was deleted, disabled or given another role: its open
     * subscriptions end (management-accounts.md 7.2). A connection keeps the identity and rights it
     * was opened with, so it would otherwise go on as the old account and receive what clients send
     * to a later account of the same name.
     */
    public void closeIdentity(String tenantId, String username, String reason) {
        Set<WebSocketSession> sessions = adminSessions.remove(adminSessionKey(tenantId, username));
        if (sessions == null) {
            return;
        }
        for (WebSocketSession session : sessions) {
            try {
                session.close(CloseStatus.POLICY_VIOLATION.withReason(reason));
            } catch (Exception e) {
                log.debug("client-message websocket close failed: {}", e.getMessage());
            }
        }
    }

    private void send(WebSocketSession session, Object payload) throws Exception {
        if (session.isOpen()) {
            synchronized (session) {
                if (session.isOpen()) {
                    session.sendMessage(new TextMessage(objectMapper.writeValueAsString(payload)));
                }
            }
        }
    }

    private void sendError(WebSocketSession session, String error, ClientMessageCommand command) throws Exception {
        send(session, Map.of(
                "type", "error",
                "error", error,
                "messageId", command.messageId() == null ? "" : command.messageId()));
    }

    private void unregister(WebSocketSession session) {
        Set<WebSocketSession> sessions = adminSessions.get(adminSessionKey(session));
        if (sessions != null) {
            sessions.remove(session);
            if (sessions.isEmpty()) {
                adminSessions.remove(adminSessionKey(session));
            }
        }
    }

    private static String adminSessionKey(WebSocketSession session) {
        return adminSessionKey(
                attr(session, WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID),
                attr(session, WebSocketTicketHandshakeInterceptor.ATTR_USER));
    }

    private static String adminSessionKey(String tenantId, String username) {
        return (tenantId == null ? "" : tenantId.trim()) + "\n" + (username == null ? "" : username.trim());
    }

    private static String normalizeAdminTarget(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        if (!trimmed.regionMatches(true, 0, "admin:", 0, "admin:".length())) {
            return "";
        }
        return trimmed.substring("admin:".length()).trim();
    }

    private static String attr(WebSocketSession session, String key) {
        Object value = session.getAttributes().get(key);
        return value == null ? "" : String.valueOf(value);
    }

    private record ClientMessageCommand(String type, String messageId, String toClientName, String message) {
    }
}
