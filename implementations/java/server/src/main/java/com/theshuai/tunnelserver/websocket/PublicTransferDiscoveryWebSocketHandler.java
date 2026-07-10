package com.theshuai.tunnelserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.theshuai.tunnelserver.config.PublicTransferProperties;
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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
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

    private final PublicTransferProperties properties;
    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet();
    private final Map<String, Participant> participantsBySession = new ConcurrentHashMap<>();
    private final Map<String, RateWindow> messageWindowsBySession = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper()
            .setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    public PublicTransferDiscoveryWebSocketHandler(PublicTransferProperties properties) {
        this.properties = properties;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        // Tomcat/Spring 默认单条消息缓冲仅 8KB,而 offer SDP(尤其携带 TURN candidate 时)常超过 8KB。
        // 抬到 MAX_MESSAGE_CHARS(64KB),让 Spring 按此上限重组分片消息,避免大信令被拒/截断导致直连失败;
        // 超过该上限由 handleTextMessage 显式以 TOO_BIG 关闭,而非底层静默断连。
        session.setTextMessageSizeLimit(MAX_MESSAGE_CHARS);
        session.setBinaryMessageSizeLimit(MAX_MESSAGE_CHARS);
        Participant participant = Participant.from(session);
        if (roomPeerCount(participant) >= Math.max(1, properties.getMaxDiscoveryPeersPerRoom())) {
            send(session, Map.of("type", "error", "error", "room is full"));
            closeQuietly(session, CloseStatus.POLICY_VIOLATION);
            return;
        }
        sessions.add(session);
        participantsBySession.put(session.getId(), participant);
        messageWindowsBySession.put(session.getId(), new RateWindow(System.currentTimeMillis()));
        send(session, Map.of(
                "type", "hello",
                "peerId", participant.peerId(),
                "roomId", participant.roomId(),
                "publicAddress", participant.publicAddress(),
                "sharedRoom", participant.sharedRoom(),
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
        if (!allowMessage(session)) {
            send(session, Map.of("type", "error", "error", "rate limited"));
            closeQuietly(session, CloseStatus.POLICY_VIOLATION);
            return;
        }
        try {
            JsonNode node = objectMapper.readTree(payload);
            if ("ping".equals(text(node, "type"))) {
                send(session, Map.of("type", "pong", "ts", Instant.now().toString()));
                return;
            }
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
        messageWindowsBySession.remove(session.getId());
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
                    view.put("sharedRoom", peer.sharedRoom());
                    view.put("connectedAt", peer.connectedAt());
                    return view;
                })
                .toList();
        Map<String, Object> payload = Map.of(
                "type", "roster",
                "roomId", group.roomId(),
                "publicAddress", group.publicAddress(),
                "sharedRoom", group.sharedRoom(),
                "peers", peers
        );
        broadcastToGroup(group, payload, false);
    }

    private long roomPeerCount(Participant group) {
        return participantsBySession.values().stream()
                .filter(peer -> peer.sameGroup(group))
                .count();
    }

    private boolean allowMessage(WebSocketSession session) {
        int limit = Math.max(1, properties.getDiscoveryMessageRateLimitPerConnection());
        long windowMillis = Math.max(1L, properties.getDiscoveryMessageRateLimitWindowSeconds()) * 1000L;
        RateWindow window = messageWindowsBySession.computeIfAbsent(
                session.getId(),
                ignored -> new RateWindow(System.currentTimeMillis())
        );
        return window.allow(limit, windowMillis, System.currentTimeMillis());
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
            messageWindowsBySession.remove(deadSession.getId());
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
            String roomKey,
            boolean sharedRoom,
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
                    stringAttr(attrs, "roomKey", "public:unknown"),
                    Boolean.TRUE.equals(attrs.get("sharedRoom")),
                    Instant.now().toString()
            );
        }

        private boolean sameGroup(Participant other) {
            return roomId.equals(other.roomId) && roomKey.equals(other.roomKey);
        }

        private static String stringAttr(Map<String, Object> attrs, String key, String fallback) {
            Object value = attrs.get(key);
            if (value instanceof String text && StringUtils.hasText(text)) {
                return text;
            }
            return fallback;
        }
    }

    private static final class RateWindow {
        private long startedAtMs;
        private int count;

        private RateWindow(long startedAtMs) {
            this.startedAtMs = startedAtMs;
        }

        private synchronized boolean allow(int limit, long windowMillis, long nowMs) {
            if (nowMs - startedAtMs >= windowMillis) {
                startedAtMs = nowMs;
                count = 0;
            }
            count += 1;
            return count <= limit;
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
            String publicAddress = publicAddress(request);
            String roomToken = query(params, "roomToken", "", 512);
            boolean sharedRoom = StringUtils.hasText(roomToken);
            attributes.put("publicAddress", publicAddress);
            attributes.put("sharedRoom", sharedRoom);
            attributes.put("roomKey", sharedRoom ? "token:" + sha256(roomToken) : "public:" + publicAddress);
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
            return truncateUtf16WithoutSplittingSurrogate(normalized, maxLength);
        }

        static String truncateUtf16WithoutSplittingSurrogate(String value, int maxLength) {
            if (value == null || value.length() <= maxLength) {
                return value;
            }
            int end = Math.max(0, maxLength);
            if (end > 0
                    && end < value.length()
                    && Character.isHighSurrogate(value.charAt(end - 1))
                    && Character.isLowSurrogate(value.charAt(end))) {
                end--;
            }
            return value.substring(0, end);
        }

        private static String publicAddress(ServerHttpRequest request) {
            if (request instanceof ServletServerHttpRequest servletRequest) {
                HttpServletRequest raw = servletRequest.getServletRequest();
                // X-Real-IP 由可信反代覆写(nginx: proxy_set_header X-Real-IP $remote_addr),
                // 客户端无法伪造,优先采信。
                String realIp = raw.getHeader("X-Real-IP");
                if (StringUtils.hasText(realIp)) {
                    return realIp.trim();
                }
                // 退而取 X-Forwarded-For 末位:反代用 $proxy_add_x_forwarded_for 追加,
                // 末段是紧邻的可信来源;取首段会被客户端自带的 XFF 头伪造,借以冒充他人 IP
                // 加入其 public:<ip> 房间(绕过"附近设备"隔离)。
                String forwarded = lastForwarded(raw.getHeader("X-Forwarded-For"));
                if (StringUtils.hasText(forwarded)) {
                    return forwarded;
                }
            }
            return request.getRemoteAddress() == null
                    ? "unknown"
                    : request.getRemoteAddress().getAddress().getHostAddress();
        }

        private static String lastForwarded(String value) {
            if (!StringUtils.hasText(value)) {
                return "";
            }
            String[] parts = value.split(",");
            return parts.length == 0 ? "" : parts[parts.length - 1].trim();
        }

        private static String sha256(String value) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception e) {
                throw new IllegalStateException("failed to hash room token", e);
            }
        }
    }
}
