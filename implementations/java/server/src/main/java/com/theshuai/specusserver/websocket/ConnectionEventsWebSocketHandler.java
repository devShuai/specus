package com.theshuai.specusserver.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@code /ws/connections} 的服务端 handler：管理所有在线管理浏览器的 WebSocket session，
 * 提供 {@link #broadcast(String, Object)} 把对象序列化为 JSON 推给同租户 session。
 *
 * <p>设计要点：
 * <ul>
 *   <li>session 集合用 {@link ConcurrentHashMap#newKeySet()}，事件循环跨线程访问安全。</li>
 *   <li>broadcast 时遇到写失败的 session 立即移除并 close，避免堆积已死连接拖慢后续推送。</li>
 *   <li>handler 自身不依赖 Service 层，由 {@link ConnectionEventBroadcaster} 单向调用，
 *       避免与 {@code ConnectionRecordService} 形成循环依赖。</li>
 *   <li>Spring Boot 4.1 默认 JSON 库切换到 {@code tools.jackson.databind.json.JsonMapper}，
 *       不再注册经典 {@code com.fasterxml.jackson.databind.ObjectMapper} bean；这里自己 new 一个，
 *       零依赖、与 REST 层 JSON 配置解耦，行为可控。</li>
 * </ul>
 */
@Component
public class ConnectionEventsWebSocketHandler extends TextWebSocketHandler {
    private static final Logger log = LoggerFactory.getLogger(ConnectionEventsWebSocketHandler.class);

    private final ClientAccountRepository clientAccountRepository;
    private final PublicTransferCoordinationService coordination;
    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet();
    private final ObjectMapper objectMapper = new ObjectMapper()
            // null 字段省略，前端不需要看到全是 null 的列；体积也更小
            .setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    public ConnectionEventsWebSocketHandler(ClientAccountRepository clientAccountRepository,
                                            PublicTransferCoordinationService coordination) {
        this.clientAccountRepository = clientAccountRepository;
        this.coordination = coordination;
        coordination.addListener(this::handleClusterEvent);
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        sessions.add(session);
        log.debug("ws session established: {} (total={})", session.getId(), sessions.size());
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session);
        log.debug("ws session closed: {} status={} (total={})", session.getId(), status, sessions.size());
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        log.debug("ws transport error on {}: {}", session.getId(),
                exception == null ? "null" : exception.toString());
        // session 会被框架进一步关闭并触发 afterConnectionClosed
    }

    /** 把 {@code payload} 序列化为 JSON，推给当前租户所有在线 session。 */
    public void broadcast(String tenantId, Object payload) {
        byte[] json;
        try {
            json = objectMapper.writeValueAsBytes(payload);
        } catch (Exception e) {
            log.warn("serialize websocket payload failed: {}", e.toString());
            return;
        }

        if (coordination.enabled() && payload instanceof ConnectionEvent) {
            try {
                coordination.publishManagement(tenantId, json);
                return;
            } catch (RuntimeException exception) {
                log.warn("publish management connection event failed; using local delivery: {}",
                        exception.toString());
            }
        }
        broadcastLocal(tenantId, payload, json);
    }

    private void handleClusterEvent(PublicTransferClusterFrame.Event clusterEvent) {
        if (clusterEvent.kind() != PublicTransferClusterFrame.KIND_MANAGEMENT) {
            return;
        }
        try {
            ConnectionEvent event = objectMapper.readValue(clusterEvent.payload(), ConnectionEvent.class);
            if (event.tenantId() == null
                    || !clusterEvent.groupId().equals(
                    PublicTransferCoordinationService.managementGroupId(event.tenantId()))) {
                log.warn("discarding management cluster event with invalid tenant binding");
                return;
            }
            broadcastLocal(event.tenantId(), event, clusterEvent.payload());
        } catch (Exception exception) {
            log.warn("discarding invalid management cluster event: {}", exception.getMessage());
        }
    }

    private void broadcastLocal(String tenantId, Object payload, byte[] json) {
        if (sessions.isEmpty()) {
            return;
        }
        TextMessage message = new TextMessage(json);
        for (WebSocketSession session : sessions) {
            Object sessionTenantId = session.getAttributes().get(WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID);
            if (!tenantId.equals(sessionTenantId)) {
                continue;
            }
            if (!canReceive(session, tenantId, payload)) {
                continue;
            }
            if (!session.isOpen()) {
                sessions.remove(session);
                continue;
            }
            try {
                // WebSocketSession 不保证多线程写安全；同 session 串行化由 synchronized 兜底。
                synchronized (session) {
                    session.sendMessage(message);
                }
            } catch (IOException | IllegalStateException e) {
                log.debug("ws send failed for {}: {}", session.getId(), e.toString());
                sessions.remove(session);
                try {
                    session.close(CloseStatus.SERVER_ERROR);
                } catch (IOException ignored) {
                    // best-effort
                }
            }
        }
    }

    int activeSessionCount() {
        return sessions.size();
    }

    private boolean canReceive(WebSocketSession session, String tenantId, Object payload) {
        if (Boolean.TRUE.equals(session.getAttributes().get(WebSocketTicketHandshakeInterceptor.ATTR_ADMIN))) {
            return true;
        }
        if (!(payload instanceof ConnectionEvent event) || event.connection() == null) {
            return false;
        }
        Long clientId = event.connection().clientId();
        Object username = session.getAttributes().get(WebSocketTicketHandshakeInterceptor.ATTR_USER);
        return clientId != null
                && username instanceof String owner
                && clientAccountRepository
                        .findByIdAndTenantIdAndOwnerUsername(clientId, tenantId, owner)
                        .isPresent();
    }
}
