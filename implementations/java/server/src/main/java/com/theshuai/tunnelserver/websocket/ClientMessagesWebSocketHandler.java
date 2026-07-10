package com.theshuai.tunnelserver.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.ClientSession;
import com.theshuai.tunnelserver.management.repository.ClientSessionRepository;
import com.theshuai.tunnelserver.management.service.ClientAccountService;
import com.theshuai.tunnelserver.management.service.ClientAuthService;
import com.theshuai.tunnelserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.time.Instant;
import java.util.List;
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
    private final ClientSessionRepository clientSessionRepository;
    private final Map<String, Set<WebSocketSession>> adminSessions = new ConcurrentHashMap<>();

    public ClientMessagesWebSocketHandler(ClientAccountService clientAccountService,
                                          ClientSessionRepository clientSessionRepository) {
        this.clientAccountService = clientAccountService;
        this.clientSessionRepository = clientSessionRepository;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        // Keep the container aggregation limit aligned with the explicit 64K character guard.
        // Tomcat/Spring otherwise defaults to a much smaller text-message buffer.
        session.setTextMessageSizeLimit(MAX_MESSAGE_CHARS);
        session.setBinaryMessageSizeLimit(MAX_MESSAGE_CHARS);
        adminSessions.computeIfAbsent(adminSessionKey(session), ignored -> ConcurrentHashMap.newKeySet()).add(session);
        send(session, Map.of(
                "type", "hello",
                "channel", "client-messages",
                "username", attr(session, JwtHandshakeInterceptor.ATTR_USER),
                "tenantId", attr(session, JwtHandshakeInterceptor.ATTR_TENANT_ID)));
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
        if (target == null || !target.isEnabled() || !canAccess(session, target)) {
            sendError(session, "target-not-found", command);
            return;
        }
        if (!targetCanReceiveMessage(target)) {
            sendError(session, "target-cannot-receive-message", command);
            return;
        }
        Channel channel = SessionUtil.getChannel(target.getClientName());
        if (channel == null || !SessionUtil.hasLogin(channel)) {
            sendError(session, "target-offline", command);
            return;
        }

        MessageResponsePacket packet = new MessageResponsePacket();
        packet.setClientName("admin:" + attr(session, JwtHandshakeInterceptor.ATTR_USER));
        packet.setToClientName(target.getClientName());
        packet.setMessageType(MessageType.CLIENT_TO_CLIENT);
        packet.setMessage(body);
        channel.writeAndFlush(packet).addListener(future -> {
            if (!future.isSuccess()) {
                log.warn("admin client-message delivery failed: target={}, reason={}",
                        target.getClientName(),
                        future.cause() == null ? "unknown" : future.cause().getMessage());
            }
        });
        send(session, Map.of(
                "type", "sent",
                "messageId", command.messageId() == null ? "" : command.messageId(),
                "toClientName", target.getClientName(),
                "message", body));
    }

    public boolean deliverFromClient(ClientAccount source, String targetAdminName, String body) {
        String username = normalizeAdminTarget(targetAdminName);
        if (source == null || username.isBlank() || body == null || body.isBlank()) {
            return false;
        }
        Set<WebSocketSession> sessions = adminSessions.get(adminSessionKey(source.getTenantId(), username));
        if (sessions == null || sessions.isEmpty()) {
            return false;
        }
        Map<String, Object> payload = Map.of(
                "type", "message",
                "direction", "in",
                "fromClientName", source.getClientName(),
                "toClientName", "admin:" + username,
                "message", body,
                "createdAt", Instant.now().toString());
        boolean delivered = false;
        for (WebSocketSession session : sessions) {
            if (!session.isOpen()) {
                sessions.remove(session);
                continue;
            }
            try {
                send(session, payload);
                delivered = true;
            } catch (Exception e) {
                log.warn("client-message websocket delivery failed: source={}, admin={}, reason={}",
                        source.getClientName(), username, e.getMessage());
            }
        }
        return delivered;
    }

    private boolean targetCanReceiveMessage(ClientAccount target) {
        List<ClientSession> sessions = clientSessionRepository.findByTenantIdAndClientIdInAndStatus(
                target.getTenantId(),
                List.of(target.getId()),
                ClientAuthService.STATUS_NETTY_ONLINE);
        return sessions.stream().anyMatch(ClientSession::isMessageReceiveCapable);
    }

    private boolean canAccess(WebSocketSession session, ClientAccount target) {
        String tenantId = attr(session, JwtHandshakeInterceptor.ATTR_TENANT_ID);
        boolean admin = Boolean.TRUE.equals(session.getAttributes().get(JwtHandshakeInterceptor.ATTR_ADMIN));
        String username = attr(session, JwtHandshakeInterceptor.ATTR_USER);
        if (!target.getTenantId().equals(tenantId)) {
            return false;
        }
        return admin || username.equals(target.getOwnerUsername());
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
                attr(session, JwtHandshakeInterceptor.ATTR_TENANT_ID),
                attr(session, JwtHandshakeInterceptor.ATTR_USER));
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
