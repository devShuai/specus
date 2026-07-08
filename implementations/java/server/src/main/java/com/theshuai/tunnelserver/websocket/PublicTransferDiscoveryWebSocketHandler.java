package com.theshuai.tunnelserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class PublicTransferDiscoveryWebSocketHandler extends TextWebSocketHandler {
    private static final Logger log = LoggerFactory.getLogger(PublicTransferDiscoveryWebSocketHandler.class);
    private static final int MAX_MESSAGE_CHARS = 64 * 1024;

    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet();
    private final Map<String, Participant> participantsBySession = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper()
            .setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        Participant participant = Participant.from(session);
        sessions.add(session);
        participantsBySession.put(session.getId(), participant);
        send(session, Map.of(
                "type", "hello",
                "peerId", participant.peerId(),
                "roomId", participant.roomId(),
                "publicAddress", participant.publicAddress(),
                "connectedAt", participant.connectedAt()
        ));
        broadcastRoster(participant);
        log.debug("public transfer discovery joined: peer={} room={} publicAddress={}",
                participant.peerId(), participant.roomId(), participant.publicAddress());
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        Participant source = participantsBySession.get(session.getId());
        if (source == null) {
            return;
        }
        String payload = message.getPayload();
        if (payload == null || payload.length() > MAX_MESSAGE_CHARS) {
            closeQuietly(session, CloseStatus.TOO_BIG_TO_PROCESS);
            return;
        }
        try {
            JsonNode node = objectMapper.readTree(payload);
            String targetPeerId = text(node, "targetPeerId");
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("type", text(node, "type", "signal"));
            envelope.put("sourcePeerId", source.peerId());
            envelope.put("targetPeerId", StringUtils.hasText(targetPeerId) ? targetPeerId : null);
            envelope.put("roomId", source.roomId());
            envelope.put("publicAddress", source.publicAddress());
            envelope.put("payload", node.get("payload"));
            if (StringUtils.hasText(targetPeerId)) {
                sendToPeer(source, targetPeerId, envelope);
            } else {
                broadcastToGroup(source, envelope, true);
            }
        } catch (Exception e) {
            send(session, Map.of("type", "error", "error", "invalid message"));
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session);
        Participant removed = participantsBySession.remove(session.getId());
        if (removed != null) {
            broadcastRoster(removed);
        }
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        log.debug("public transfer discovery transport error: {}",
                exception == null ? "null" : exception.toString());
    }

    private void sendToPeer(Participant source, String targetPeerId, Object payload) {
        for (WebSocketSession session : sessions) {
            Participant target = participantsBySession.get(session.getId());
            if (target != null && target.sameGroup(source) && target.peerId().equals(targetPeerId)) {
                send(session, payload);
                return;
            }
        }
    }

    private void broadcastRoster(Participant group) {
        List<Map<String, Object>> peers = participantsBySession.values().stream()
                .filter(peer -> peer.sameGroup(group))
                .sorted(Comparator.comparing(Participant::connectedAt))
                .map(peer -> {
                    Map<String, Object> view = new LinkedHashMap<>();
                    view.put("peerId", peer.peerId());
                    view.put("displayName", peer.displayName());
                    view.put("roomId", peer.roomId());
                    view.put("publicAddress", peer.publicAddress());
                    view.put("connectedAt", peer.connectedAt());
                    return view;
                })
                .toList();
        Map<String, Object> payload = Map.of(
                "type", "roster",
                "roomId", group.roomId(),
                "publicAddress", group.publicAddress(),
                "peers", peers
        );
        broadcastToGroup(group, payload, false);
    }

    private void broadcastToGroup(Participant group, Object payload, boolean excludeSource) {
        List<WebSocketSession> dead = new ArrayList<>();
        for (WebSocketSession session : sessions) {
            Participant peer = participantsBySession.get(session.getId());
            if (peer == null || !peer.sameGroup(group) || (excludeSource && peer.sessionId().equals(group.sessionId()))) {
                continue;
            }
            if (!send(session, payload)) {
                dead.add(session);
            }
        }
        dead.forEach(deadSession -> {
            sessions.remove(deadSession);
            participantsBySession.remove(deadSession.getId());
            closeQuietly(deadSession, CloseStatus.SERVER_ERROR);
        });
    }

    private boolean send(WebSocketSession session, Object payload) {
        if (!session.isOpen()) {
            return false;
        }
        try {
            String json = objectMapper.writeValueAsString(payload);
            synchronized (session) {
                session.sendMessage(new TextMessage(json));
            }
            return true;
        } catch (IOException | IllegalStateException e) {
            log.debug("public transfer discovery send failed: {}", e.toString());
            return false;
        }
    }

    private void closeQuietly(WebSocketSession session, CloseStatus status) {
        try {
            session.close(status);
        } catch (IOException ignored) {
            // best-effort
        }
    }

    private static String text(JsonNode node, String field) {
        return text(node, field, "");
    }

    private static String text(JsonNode node, String field, String fallback) {
        JsonNode value = node == null ? null : node.get(field);
        return value == null || value.isNull() ? fallback : value.asText(fallback);
    }

    private record Participant(
            String sessionId,
            String peerId,
            String displayName,
            String roomId,
            String publicAddress,
            String connectedAt
    ) {
        private static Participant from(WebSocketSession session) {
            Map<String, Object> attrs = session.getAttributes();
            return new Participant(
                    session.getId(),
                    stringAttr(attrs, "peerId", "web-" + UUID.randomUUID().toString().substring(0, 8)),
                    stringAttr(attrs, "displayName", "web"),
                    stringAttr(attrs, "roomId", "nearby"),
                    stringAttr(attrs, "publicAddress", "unknown"),
                    Instant.now().toString()
            );
        }

        private boolean sameGroup(Participant other) {
            return roomId.equals(other.roomId) && publicAddress.equals(other.publicAddress);
        }

        private static String stringAttr(Map<String, Object> attrs, String key, String fallback) {
            Object value = attrs.get(key);
            if (value instanceof String text && StringUtils.hasText(text)) {
                return text;
            }
            return fallback;
        }
    }

    public static final class PublicTransferDiscoveryHandshakeInterceptor implements HandshakeInterceptor {
        @Override
        public boolean beforeHandshake(ServerHttpRequest request, org.springframework.http.server.ServerHttpResponse response,
                                       org.springframework.web.socket.WebSocketHandler wsHandler,
                                       Map<String, Object> attributes) {
            Map<String, List<String>> params = UriComponentsBuilder.fromUri(request.getURI())
                    .build()
                    .getQueryParams();
            attributes.put("roomId", query(params, "roomId", "nearby", 120));
            attributes.put("peerId", query(params, "peerId", "", 120));
            attributes.put("displayName", query(params, "displayName", "web", 120));
            attributes.put("publicAddress", publicAddress(request));
            return true;
        }

        @Override
        public void afterHandshake(ServerHttpRequest request, org.springframework.http.server.ServerHttpResponse response,
                                   org.springframework.web.socket.WebSocketHandler wsHandler, Exception exception) {
            // no-op
        }

        private static String query(Map<String, List<String>> params, String name, String fallback, int maxLength) {
            List<String> values = params.get(name);
            String value = values == null || values.isEmpty() ? fallback : values.get(0);
            if (!StringUtils.hasText(value)) {
                return fallback;
            }
            String normalized = value.trim();
            return normalized.length() > maxLength ? normalized.substring(0, maxLength) : normalized;
        }

        private static String publicAddress(ServerHttpRequest request) {
            if (request instanceof ServletServerHttpRequest servletRequest) {
                HttpServletRequest raw = servletRequest.getServletRequest();
                String forwarded = firstForwarded(raw.getHeader("X-Forwarded-For"));
                if (StringUtils.hasText(forwarded)) {
                    return forwarded;
                }
                forwarded = firstForwarded(raw.getHeader("X-Real-IP"));
                if (StringUtils.hasText(forwarded)) {
                    return forwarded;
                }
            }
            return request.getRemoteAddress() == null
                    ? "unknown"
                    : request.getRemoteAddress().getAddress().getHostAddress();
        }

        private static String firstForwarded(String value) {
            if (!StringUtils.hasText(value)) {
                return "";
            }
            return value.split(",", 2)[0].trim();
        }
    }
}
