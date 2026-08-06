package com.theshuai.specusserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.theshuai.specusserver.config.PublicTransferProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.socket.BinaryMessage;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.AbstractWebSocketHandler;

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
import java.util.concurrent.atomic.AtomicLong;

@Component
public class PublicTransferDiscoveryWebSocketHandler extends AbstractWebSocketHandler {
    private static final Logger log = LoggerFactory.getLogger(PublicTransferDiscoveryWebSocketHandler.class);
    private static final int MAX_MESSAGE_CHARS = 64 * 1024;
    private static final int MAX_DISPLAY_NAME_LENGTH = 120;
    private static final Set<String> VIEWER_WRITE_MESSAGE_TYPES = Set.of("attachment", "clipboard", "whiteboard");

    private final PublicTransferProperties properties;
    private final PublicTransferCoordinationService coordination;
    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet();
    private final Map<String, Participant> participantsBySession = new ConcurrentHashMap<>();
    private final Map<String, RateWindow> messageWindowsBySession = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> localRosterRevisions = new ConcurrentHashMap<>();
    private final Object participantJoinLock = new Object();
    private final ObjectMapper objectMapper = new ObjectMapper()
            .setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    @Autowired
    public PublicTransferDiscoveryWebSocketHandler(PublicTransferProperties properties,
                                                   PublicTransferCoordinationService coordination) {
        this.properties = properties;
        this.coordination = coordination;
        coordination.addListener(this::handleCoordinationEvent);
    }

    PublicTransferDiscoveryWebSocketHandler(PublicTransferProperties properties) {
        this(properties, new PublicTransferCoordinationService(properties));
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        // Tomcat/Spring 默认单条消息缓冲仅 8KB,而 offer SDP(尤其携带 TURN candidate 时)常超过 8KB。
        // 抬到 MAX_MESSAGE_CHARS(64KB),让 Spring 按此上限重组分片消息,避免大信令被拒/截断导致直连失败;
        // 超过该上限由 handleTextMessage 显式以 TOO_BIG 关闭,而非底层静默断连。
        session.setTextMessageSizeLimit(MAX_MESSAGE_CHARS);
        session.setBinaryMessageSizeLimit(MAX_MESSAGE_CHARS);
        Participant participant = Participant.from(session);
        try {
            participant = participant.withDisplayName(normalizeDisplayName(participant.displayName()));
        } catch (IllegalArgumentException exception) {
            send(session, Map.of("type", "error", "error", exception.getMessage()));
            closeQuietly(session, CloseStatus.POLICY_VIOLATION);
            return;
        }
        String joinError = null;
        long rosterRevision = 0;
        if (!participant.discoverable()) {
            // 隐身端不进入 roster：集群模式下不注册到共享 presence，本地 roster 亦被过滤。
            // 但它仍加入本地会话表，因此照常收到 roster 广播、也能主动发起信令与传输。
            addLocalParticipant(session, participant);
        } else if (coordination.enabled()) {
            try {
                PublicTransferCoordinationService.Registration registration = coordination.register(
                        participant.coordinationParticipant(),
                        properties.getMaxDiscoveryPeersPerRoom());
                joinError = registration.error();
                rosterRevision = registration.revision();
                if (registration.accepted()) {
                    addLocalParticipant(session, participant);
                }
            } catch (IllegalStateException exception) {
                log.warn("public transfer cluster registration failed: {}", exception.toString());
                joinError = "coordination unavailable";
            }
        } else {
            synchronized (participantJoinLock) {
                if (hasConnectedPeerId(participant)) {
                    joinError = "peer id is already connected";
                } else if (hasConnectedDisplayName(participant.displayName())) {
                    joinError = "client name is already in use";
                } else if (roomPeerCount(participant) >= Math.max(1, properties.getMaxDiscoveryPeersPerRoom())) {
                    joinError = "room is full";
                } else {
                    addLocalParticipant(session, participant);
                    rosterRevision = nextLocalRosterRevision(participant.netId());
                }
            }
        }
        if (joinError != null) {
            send(session, Map.of("type", "error", "error", joinError));
            closeQuietly(session, CloseStatus.POLICY_VIOLATION);
            return;
        }
        send(session, Map.of(
                "type", "hello",
                "peerId", participant.peerId(),
                "displayName", participant.displayName(),
                "roomId", participant.roomId(),
                "publicAddress", participant.publicAddress(),
                "sharedRoom", participant.sharedRoom(),
                "roomRole", participant.roomRole(),
                "rosterRevision", rosterRevision,
                "connectedAt", participant.connectedAt()
        ));
        broadcastRoster(participant, rosterRevision);
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
        if (!allowMessage(session, source)) {
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
            String messageType = text(node, "type", "signal");
            if ("VIEWER".equals(source.roomRole()) && VIEWER_WRITE_MESSAGE_TYPES.contains(messageType)) {
                send(session, Map.of("type", "error", "error", "viewer is read-only"));
                return;
            }
            String targetPeerId = text(node, "targetPeerId");
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("type", messageType);
            envelope.put("sourcePeerId", source.peerId());
            envelope.put("sourceRole", source.roomRole());
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
    protected void handleBinaryMessage(WebSocketSession session, BinaryMessage message) {
        Participant source = participantsBySession.get(session.getId());
        if (source == null) {
            return;
        }
        if (!allowMessage(session, source)) {
            send(session, Map.of("type", "error", "error", "rate limited"));
            closeQuietly(session, CloseStatus.POLICY_VIOLATION);
            return;
        }
        try {
            PublicTransferRelayFrame.ClientFrame frame =
                    PublicTransferRelayFrame.decodeClient(message.getPayload());
            if ("VIEWER".equals(source.roomRole())
                    && frame.appType() != PublicTransferRelayFrame.APP_TYPE_ACK) {
                send(session, Map.of("type", "error", "error", "viewer is read-only"));
                return;
            }
            sendBinaryToPeer(source, frame);
        } catch (IllegalArgumentException exception) {
            send(session, Map.of("type", "error", "error", "invalid binary relay frame"));
            closeQuietly(session, CloseStatus.POLICY_VIOLATION);
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session);
        Participant removed = participantsBySession.remove(session.getId());
        messageWindowsBySession.remove(session.getId());
        if (removed != null) {
            if (coordination.enabled()) {
                try {
                    long revision = coordination.unregister(removed.coordinationParticipant());
                    if (revision > 0) {
                        // 注销影响同房间与同网两个维度的 roster,两个 audience 都要推送。
                        coordination.publishRoster(removed.groupId(), revision);
                        coordination.publishRoster(removed.netId(), revision);
                    }
                } catch (IllegalStateException exception) {
                    log.warn("public transfer cluster unregister failed: {}", exception.toString());
                }
            } else {
                broadcastRoster(removed, nextLocalRosterRevision(removed.netId()));
            }
        }
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        log.debug("public transfer discovery transport error: {}",
                exception == null ? "null" : exception.toString());
    }

    @Scheduled(fixedDelayString = "${specus.public-transfer.presence-refresh-interval-ms:10000}")
    public void refreshClusterPresence() {
        if (!coordination.enabled() || participantsBySession.isEmpty()) {
            return;
        }
        Set<String> groupNets = ConcurrentHashMap.newKeySet();
        Set<String> nets = ConcurrentHashMap.newKeySet();
        try {
            for (Map.Entry<String, Participant> entry : List.copyOf(participantsBySession.entrySet())) {
                Participant participant = entry.getValue();
                if (!participant.discoverable()) {
                    // 隐身端不注册集群 presence,无需续期(否则 refresh 必然失败,每个周期都会被
                    // dropLocal 踢掉);其本地会话由 WebSocket 本身保活。
                    continue;
                }
                groupNets.add(participant.groupId() + "\n" + participant.netId());
                nets.add(participant.netId());
                if (!coordination.refresh(participant.coordinationParticipant())) {
                    WebSocketSession session = sessions.stream()
                            .filter(candidate -> candidate.getId().equals(entry.getKey()))
                            .findFirst()
                            .orElse(null);
                    if (session != null) {
                        dropLocal(session, CloseStatus.SERVER_ERROR);
                    }
                }
            }
            // presence 过期清扫保持按 group(groupId/netId 均为 sha256 hex,"\n" 仅作本地分隔)。
            groupNets.forEach(groupNet -> {
                int separator = groupNet.indexOf('\n');
                coordination.sweep(groupNet.substring(0, separator), groupNet.substring(separator + 1));
            });
            // 过期成员的同网跨房间 audience 不在被清扫 group 的推送范围内,补一次按 net 的 roster
            // 推送;事件 revision 仅作占位,接收端会按 netId 重新读取一致快照与单调 revision。
            nets.forEach(netId -> coordination.publishRoster(netId, 0));
        } catch (IllegalStateException exception) {
            log.warn("public transfer Redis coordination unavailable; closing local discovery sockets: {}",
                    exception.toString());
            List.copyOf(sessions).forEach(session -> dropLocal(session, CloseStatus.SERVER_ERROR));
        }
    }

    private void handleCoordinationEvent(PublicTransferClusterFrame.Event event) {
        // 事件的 group 字段是不透明标识:roster 事件可能是 groupId 或 netId,定向事件恒为目标
        // 所在 groupId;两种标识都不可能与另一维度撞名(sha256 域分离由内容保证),合并匹配即可。
        Participant group = participantsBySession.values().stream()
                .filter(participant -> participant.groupId().equals(event.groupId())
                        || participant.netId().equals(event.groupId()))
                .findFirst()
                .orElse(null);
        if (group == null) {
            return;
        }
        try {
            switch (event.kind()) {
                case PublicTransferClusterFrame.KIND_ROSTER -> emitRoster(group);
                case PublicTransferClusterFrame.KIND_TEXT -> {
                    JsonNode payload = objectMapper.readTree(event.payload());
                    deliverClusterText(group, event, payload);
                }
                case PublicTransferClusterFrame.KIND_BINARY -> deliverClusterBinary(group, event);
                default -> throw new IllegalArgumentException("unsupported cluster event kind");
            }
        } catch (Exception exception) {
            log.warn("discarding public transfer cluster event: {}", exception.toString());
        }
    }

    private void deliverClusterText(Participant group,
                                    PublicTransferClusterFrame.Event event,
                                    JsonNode payload) {
        for (WebSocketSession session : sessions) {
            Participant target = participantsBySession.get(session.getId());
            if (target == null || !(target.groupId().equals(event.groupId())
                    || target.netId().equals(event.groupId()))) {
                continue;
            }
            if (StringUtils.hasText(event.targetPeerId())
                    && !target.peerId().equals(event.targetPeerId())) {
                continue;
            }
            if (event.excludeSource() && target.leaseId().equals(event.sourceLeaseId())) {
                continue;
            }
            send(session, payload);
        }
    }

    private void deliverClusterBinary(Participant group, PublicTransferClusterFrame.Event event) {
        for (WebSocketSession session : sessions) {
            Participant target = participantsBySession.get(session.getId());
            if (target != null
                    && (target.groupId().equals(event.groupId())
                            || target.netId().equals(event.groupId()))
                    && target.peerId().equals(event.targetPeerId())) {
                sendBinary(session, event.payload());
                return;
            }
        }
    }

    private void addLocalParticipant(WebSocketSession session, Participant participant) {
        sessions.add(session);
        participantsBySession.put(session.getId(), participant);
        messageWindowsBySession.put(session.getId(), new RateWindow(System.currentTimeMillis()));
    }

    private void dropLocal(WebSocketSession session, CloseStatus status) {
        sessions.remove(session);
        participantsBySession.remove(session.getId());
        messageWindowsBySession.remove(session.getId());
        closeQuietly(session, status);
    }

    private long nextLocalRosterRevision(String netId) {
        return localRosterRevisions.computeIfAbsent(netId, ignored -> new AtomicLong()).incrementAndGet();
    }

    private byte[] encodeJson(Object payload) {
        try {
            return objectMapper.writeValueAsBytes(payload);
        } catch (IOException exception) {
            throw new IllegalArgumentException("could not encode discovery message", exception);
        }
    }

    private Map<String, Object> participantView(Participant peer, Participant recipient) {
        return participantView(peer.peerId(), peer.displayName(), peer.roomId(), peer.publicAddress(),
                peer.sharedRoom(), peer.roomRole(), peer.connectedAt(),
                peer.roomKey().equals(recipient.roomKey()));
    }

    private Map<String, Object> participantView(PublicTransferCoordinationService.Participant peer,
                                                Participant recipient) {
        return participantView(peer.peerId(), peer.displayName(), peer.roomId(), peer.publicAddress(),
                peer.sharedRoom(), peer.roomRole(), peer.connectedAt(),
                peer.roomKey().equals(recipient.roomKey()));
    }

    private Map<String, Object> participantView(String peerId, String displayName, String roomId,
                                                String publicAddress, boolean sharedRoom,
                                                String roomRole, String connectedAt, boolean sameRoom) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("peerId", peerId);
        view.put("displayName", displayName);
        view.put("roomId", roomId);
        view.put("publicAddress", publicAddress);
        view.put("sharedRoom", sharedRoom);
        view.put("roomRole", roomRole);
        view.put("connectedAt", connectedAt);
        // 逐接收者标注"同房间"(roomKey 相等),替代暴露 roomKey 本体(房间数字 ID 不外泄)。
        view.put("sameRoom", sameRoom);
        return view;
    }

    private void sendToPeer(Participant source, String targetPeerId, Object payload) {
        if (coordination.enabled()) {
            // 定向路由的可见域是同房间+同网:在合并 roster 内解析目标,按目标所在 group 投递。
            // 同房间目标解析到的就是 source 所在 group,与旧行为一致;事件格式不变。
            PublicTransferCoordinationService.Participant target =
                    coordination.findPeer(source.coordinationParticipant(), targetPeerId);
            // 回退语义:隐身端(discoverable=false)不注册共享 presence,findPeer 解析不到;
            // 此时退回按 source 所在 group 投递,使同 group 隐身端仍能收到定向应答(例如隐身端
            // 先发起 offer 后,对端的 answer 必须可达)——与改造前的集群行为一致。跨房间同网的
            // 隐身端依旧不可达,这也与旧行为一致。
            coordination.publishText(target == null ? source.groupId() : target.groupId(),
                    targetPeerId, source.leaseId(), false, encodeJson(payload));
            return;
        }
        for (WebSocketSession session : sessions) {
            Participant target = participantsBySession.get(session.getId());
            if (target != null && (target.sameGroup(source) || target.sameNet(source))
                    && target.peerId().equals(targetPeerId)) {
                send(session, payload);
                return;
            }
        }
    }

    private void sendBinaryToPeer(Participant source, PublicTransferRelayFrame.ClientFrame frame) {
        byte[] envelope = PublicTransferRelayFrame.encodeServer(
                frame.targetPeerId(), source.peerId(), frame.appFrame());
        if (coordination.enabled()) {
            // 与 sendToPeer 同理,按目标所在 group 单次投递,避免双发造成的 relay 帧重复;
            // 隐身端目标不在共享 presence,解析不到时退回按 source group 投递(同 group 可达)。
            PublicTransferCoordinationService.Participant target =
                    coordination.findPeer(source.coordinationParticipant(), frame.targetPeerId());
            coordination.publishBinary(target == null ? source.groupId() : target.groupId(),
                    frame.targetPeerId(), envelope);
            return;
        }
        for (WebSocketSession session : sessions) {
            Participant target = participantsBySession.get(session.getId());
            if (target != null && (target.sameGroup(source) || target.sameNet(source))
                    && target.peerId().equals(frame.targetPeerId())) {
                sendBinary(session, envelope);
                return;
            }
        }
    }

    private void broadcastRoster(Participant group, long revision) {
        if (coordination.enabled()) {
            // roster 变更影响同房间与同网两个 audience;事件 revision 仅作占位,
            // 接收端会重新读取一致快照并带上单调 revision。
            coordination.publishRoster(group.groupId(), revision);
            coordination.publishRoster(group.netId(), revision);
            return;
        }
        emitRoster(group);
    }

    private void emitRoster(Participant group) {
        // 逐接收者构造 payload:sameRoom 是接收者相对的;每个接收者的 roster revision 按其
        // 所在 net 单调递增(集群模式下为 revision:<group> + revision:<net> 的一致快照)。
        Map<String, PublicTransferCoordinationService.Roster> clusterRosters = new LinkedHashMap<>();
        List<WebSocketSession> dead = new ArrayList<>();
        for (WebSocketSession session : sessions) {
            Participant recipient = participantsBySession.get(session.getId());
            if (recipient == null || !(recipient.sameGroup(group) || recipient.sameNet(group))) {
                continue;
            }
            List<Map<String, Object>> peers;
            long revision;
            if (coordination.enabled()) {
                PublicTransferCoordinationService.Roster roster = clusterRosters.computeIfAbsent(
                        recipient.groupId() + "\n" + recipient.netId(),
                        ignored -> coordination.roster(recipient.coordinationParticipant()));
                revision = roster.revision();
                peers = roster.participants().stream()
                        .map(peer -> participantView(peer, recipient))
                        .toList();
            } else {
                peers = participantsBySession.values().stream()
                        .filter(peer -> peer.sameGroup(recipient) || peer.sameNet(recipient))
                        .filter(Participant::discoverable)
                        .sorted(Comparator.comparing(Participant::connectedAt))
                        .map(peer -> participantView(peer, recipient))
                        .toList();
                revision = nextLocalRosterRevision(recipient.netId());
            }
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("type", "roster");
            payload.put("roomId", recipient.roomId());
            payload.put("publicAddress", recipient.publicAddress());
            payload.put("sharedRoom", recipient.sharedRoom());
            payload.put("rosterRevision", revision);
            payload.put("peers", peers);
            if (!send(session, payload)) {
                dead.add(session);
            }
        }
        dropDeadSessions(dead);
    }

    private long roomPeerCount(Participant group) {
        return participantsBySession.values().stream()
                .filter(peer -> peer.sameGroup(group))
                .count();
    }

    private boolean hasConnectedPeerId(Participant participant) {
        // 定向路由按合并可见域(同房间或同网)投递,peerId 必须在该域内唯一,否则跨房间同 peerId 会互抢信令。
        return participantsBySession.values().stream()
                .anyMatch(peer -> (peer.sameGroup(participant) || peer.sameNet(participant))
                        && peer.peerId().equals(participant.peerId()));
    }

    private boolean hasConnectedDisplayName(String displayName) {
        return participantsBySession.values().stream()
                .anyMatch(peer -> peer.displayName().equalsIgnoreCase(displayName));
    }

    public ClientNameAvailability checkClientNameAvailability(String requestedClientName, String excludePeerId) {
        String clientName = normalizeDisplayName(requestedClientName);
        String excluded = StringUtils.hasText(excludePeerId) ? excludePeerId.trim() : "";
        boolean available;
        if (coordination.enabled()) {
            available = coordination.isClientNameAvailable(clientName, excluded);
        } else {
            synchronized (participantJoinLock) {
                available = participantsBySession.values().stream()
                        .filter(peer -> excluded.isEmpty() || !peer.peerId().equals(excluded))
                        .noneMatch(peer -> peer.displayName().equalsIgnoreCase(clientName));
            }
        }
        return new ClientNameAvailability(clientName, available);
    }

    private static String normalizeDisplayName(String requestedClientName) {
        if (!StringUtils.hasText(requestedClientName)) {
            throw new IllegalArgumentException("client name is required");
        }
        String clientName = requestedClientName.trim();
        if (clientName.length() > MAX_DISPLAY_NAME_LENGTH) {
            throw new IllegalArgumentException("client name is too long");
        }
        if (clientName.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("client name contains invalid characters");
        }
        return clientName;
    }

    private boolean allowMessage(WebSocketSession session, Participant participant) {
        int limit = Math.max(1, properties.getDiscoveryMessageRateLimitPerConnection());
        long windowSeconds = Math.max(1L, properties.getDiscoveryMessageRateLimitWindowSeconds());
        if (coordination.enabled()) {
            try {
                return coordination.allowRate(
                        "discovery-message",
                        participant.groupId() + "\n" + participant.peerId(),
                        limit,
                        windowSeconds);
            } catch (IllegalStateException exception) {
                log.warn("public transfer cluster rate limit failed: {}", exception.toString());
                return false;
            }
        }
        long windowMillis = windowSeconds * 1000L;
        RateWindow window = messageWindowsBySession.computeIfAbsent(
                session.getId(),
                ignored -> new RateWindow(System.currentTimeMillis())
        );
        return window.allow(limit, windowMillis, System.currentTimeMillis());
    }

    private void broadcastToGroup(Participant group, Object payload, boolean excludeSource) {
        if (coordination.enabled()) {
            coordination.publishText(group.groupId(), "", group.leaseId(), excludeSource,
                    encodeJson(payload));
            return;
        }
        broadcastLocal(group, payload, excludeSource, group.leaseId());
    }

    private void broadcastLocal(Participant group, Object payload, boolean excludeSource,
                                String sourceLeaseId) {
        List<WebSocketSession> dead = new ArrayList<>();
        for (WebSocketSession session : sessions) {
            Participant peer = participantsBySession.get(session.getId());
            if (peer == null || !peer.sameGroup(group)
                    || (excludeSource && peer.leaseId().equals(sourceLeaseId))) {
                continue;
            }
            if (!send(session, payload)) {
                dead.add(session);
            }
        }
        dropDeadSessions(dead);
    }

    private void dropDeadSessions(List<WebSocketSession> dead) {
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

    private boolean sendBinary(WebSocketSession session, byte[] payload) {
        if (!session.isOpen()) {
            return false;
        }
        try {
            synchronized (session) {
                session.sendMessage(new BinaryMessage(payload));
            }
            return true;
        } catch (IOException | IllegalStateException exception) {
            log.debug("public transfer discovery binary send failed: {}", exception.toString());
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
            String leaseId,
            String peerId,
            String displayName,
            String roomId,
            String publicAddress,
            String roomKey,
            String roomRole,
            boolean sharedRoom,
            boolean discoverable,
            String connectedAt
    ) {
        private static Participant from(WebSocketSession session) {
            Map<String, Object> attrs = session.getAttributes();
            return new Participant(
                    session.getId(),
                    UUID.randomUUID().toString(),
                    stringAttr(attrs, "peerId", "web-" + UUID.randomUUID().toString().substring(0, 8)),
                    stringAttr(attrs, "displayName", "web"),
                    stringAttr(attrs, "roomId", "nearby"),
                    stringAttr(attrs, "publicAddress", WebSocketRequestAddress.UNKNOWN),
                    stringAttr(attrs, "roomKey", "public:unknown"),
                    stringAttr(attrs, "roomRole", "EDITOR"),
                    Boolean.TRUE.equals(attrs.get("sharedRoom")),
                    !Boolean.FALSE.equals(attrs.get("discoverable")),
                    Instant.now().toString()
            );
        }

        private Participant withDisplayName(String normalizedDisplayName) {
            return new Participant(
                    sessionId,
                    leaseId,
                    peerId,
                    normalizedDisplayName,
                    roomId,
                    publicAddress,
                    roomKey,
                    roomRole,
                    sharedRoom,
                    discoverable,
                    connectedAt
            );
        }

        private boolean sameGroup(Participant other) {
            return roomId.equals(other.roomId) && roomKey.equals(other.roomKey);
        }

        private boolean sameNet(Participant other) {
            // 同网只看公网地址(与 roomId 无关):前端改房间名不影响同网自动发现。
            // 兜底地址("unknown"/空)不构成同网,避免无地址客户端被异常聚为一组。
            return PublicTransferCoordinationService.sameNetAddress(publicAddress, other.publicAddress);
        }

        private String groupId() {
            return PublicTransferCoordinationService.groupId(roomId, roomKey);
        }

        private String netId() {
            return PublicTransferCoordinationService.netId(publicAddress);
        }

        private PublicTransferCoordinationService.Participant coordinationParticipant() {
            return new PublicTransferCoordinationService.Participant(
                    leaseId,
                    peerId,
                    displayName,
                    roomId,
                    publicAddress,
                    roomKey,
                    roomRole,
                    sharedRoom,
                    connectedAt);
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

    public record ClientNameAvailability(String clientName, boolean available) {
    }
}
