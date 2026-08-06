package com.theshuai.specusserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.config.PublicTransferProperties;
import org.junit.jupiter.api.Test;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PublicTransferDiscoveryWebSocketHandlerTests {

    @Test
    void duplicatePeerIdInSameGroupIsRejectedBeforeJoin() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession first = session("session-1", "web-duplicate", "room-a", "token:room-a");
        WebSocketSession duplicate = session("session-2", "web-duplicate", "room-a", "token:room-a");

        handler.afterConnectionEstablished(first);
        clearInvocations(first);
        handler.afterConnectionEstablished(duplicate);

        var errorMessage = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(duplicate).sendMessage(errorMessage.capture());
        JsonNode error = new ObjectMapper().readTree(errorMessage.getValue().getPayload());
        assertEquals("error", error.path("type").asText());
        assertEquals("peer id is already connected", error.path("error").asText());
        verify(duplicate).close(CloseStatus.POLICY_VIOLATION);
        verify(first, never()).sendMessage(any(TextMessage.class));
        verify(first, never()).close(any(CloseStatus.class));
    }

    @Test
    void duplicatePeerIdAcrossSameNetIsRejectedBeforeJoin() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession first = session("session-1", "peer-x", "room-a", "room:42",
                "203.0.113.10", true, true);
        // 跨 roomId 但同网:定向路由可达,peerId 必须在 net 维度唯一。
        WebSocketSession duplicate = session("session-2", "peer-x", "room-b", "public:203.0.113.10",
                "203.0.113.10", false, true);

        handler.afterConnectionEstablished(first);
        clearInvocations(first);
        handler.afterConnectionEstablished(duplicate);

        var errorMessage = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(duplicate).sendMessage(errorMessage.capture());
        JsonNode error = new ObjectMapper().readTree(errorMessage.getValue().getPayload());
        assertEquals("peer id is already connected", error.path("error").asText());
        verify(duplicate).close(CloseStatus.POLICY_VIOLATION);
    }

    @Test
    void duplicatePeerIdInSameGroupAcrossNetsIsRejectedBeforeJoin() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession first = session("session-1", "peer-y", "room-a", "room:42",
                "203.0.113.10", true, true);
        // 同房间但不同网:group 维度的查重保持不放宽。
        WebSocketSession duplicate = session("session-2", "peer-y", "room-a", "room:42",
                "198.51.100.7", true, true);

        handler.afterConnectionEstablished(first);
        handler.afterConnectionEstablished(duplicate);

        var errorMessage = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(duplicate).sendMessage(errorMessage.capture());
        JsonNode error = new ObjectMapper().readTree(errorMessage.getValue().getPayload());
        assertEquals("peer id is already connected", error.path("error").asText());
        verify(duplicate).close(CloseStatus.POLICY_VIOLATION);
    }

    @Test
    void clientNameIsUniqueAcrossRoomsAndAvailabilityIsCaseInsensitive() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession first = session("session-1", "peer-1", "Alice", "room-a", "token:room-a");
        WebSocketSession duplicate = session("session-2", "peer-2", "alice", "room-b", "token:room-b");

        handler.afterConnectionEstablished(first);

        assertFalse(handler.checkClientNameAvailability(" ALICE ", "peer-2").available());
        assertTrue(handler.checkClientNameAvailability("Alice", "peer-1").available());

        handler.afterConnectionEstablished(duplicate);

        var errorMessage = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(duplicate).sendMessage(errorMessage.capture());
        JsonNode error = new ObjectMapper().readTree(errorMessage.getValue().getPayload());
        assertEquals("client name is already in use", error.path("error").asText());
        verify(duplicate).close(CloseStatus.POLICY_VIOLATION);
    }

    @Test
    void mergedRosterShowsSameNetAndSameRoomPeersWithSameRoomFlags() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession nearby = session("session-1", "peer-nearby", "room-a", "public:203.0.113.10",
                "203.0.113.10", false, true);
        WebSocketSession roomMate = session("session-2", "peer-room", "room-a", "room:42",
                "203.0.113.10", true, true);
        WebSocketSession remoteRoomMate = session("session-3", "peer-remote", "room-a", "room:42",
                "198.51.100.7", true, true);

        handler.afterConnectionEstablished(nearby);
        handler.afterConnectionEstablished(roomMate);
        handler.afterConnectionEstablished(remoteRoomMate);

        // 同网跨房间:互相可见,sameRoom=false;自身视图 sameRoom=true。
        Map<String, Boolean> nearbyPeers = peersById(lastRoster(nearby));
        assertEquals(Map.of("peer-nearby", true, "peer-room", false), nearbyPeers);

        // 房间成员的合并 roster:同网陌生人(false) + 远程同房间成员(true)。
        Map<String, Boolean> roomMatePeers = peersById(lastRoster(roomMate));
        assertEquals(Map.of("peer-room", true, "peer-nearby", false, "peer-remote", true),
                roomMatePeers);

        // 远程成员只能看到同房间成员,看不到另一公网出口的 nearby 设备。
        Map<String, Boolean> remotePeers = peersById(lastRoster(remoteRoomMate));
        assertEquals(Map.of("peer-remote", true, "peer-room", true), remotePeers);
    }

    @Test
    void peersOnSameNetSeeEachOtherAcrossRoomIds() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        // 同网判定不再含 roomId:同公网地址、不同房间名的参与者互相自动发现
        // (前端"创建新房间/改房间名"不再导致同网用户互相不可见)。
        WebSocketSession first = session("session-1", "peer-1", "room-a", "room:42",
                "203.0.113.10", true, true);
        WebSocketSession second = session("session-2", "peer-2", "room-b", "room:99",
                "203.0.113.10", true, true);

        handler.afterConnectionEstablished(first);
        handler.afterConnectionEstablished(second);

        assertEquals(Map.of("peer-1", true, "peer-2", false), peersById(lastRoster(first)));
        assertEquals(Map.of("peer-2", true, "peer-1", false), peersById(lastRoster(second)));
    }

    @Test
    void directedSignalReachesSameNetPeerAcrossRooms() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession nearby = session("session-1", "peer-nearby", "room-a", "public:203.0.113.10",
                "203.0.113.10", false, true);
        // 同 IP 不同 roomId:定向 signal 经同网维度可达。
        WebSocketSession roomMate = session("session-2", "peer-room", "room-b", "room:42",
                "203.0.113.10", true, true);

        handler.afterConnectionEstablished(nearby);
        handler.afterConnectionEstablished(roomMate);
        clearInvocations(roomMate);

        handler.handleTextMessage(nearby, new TextMessage(
                "{\"type\":\"signal\",\"targetPeerId\":\"peer-room\",\"payload\":{}}"));

        var signal = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(roomMate).sendMessage(signal.capture());
        JsonNode delivered = new ObjectMapper().readTree(signal.getValue().getPayload());
        assertEquals("signal", delivered.path("type").asText());
        assertEquals("peer-nearby", delivered.path("sourcePeerId").asText());
    }

    @Test
    void directedSignalToInvisiblePeerIsNotDelivered() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession nearby = session("session-1", "peer-nearby", "room-a", "public:203.0.113.10",
                "203.0.113.10", false, true);
        WebSocketSession outsider = session("session-2", "peer-outsider", "room-a", "room:42",
                "198.51.100.7", true, true);

        handler.afterConnectionEstablished(nearby);
        handler.afterConnectionEstablished(outsider);
        clearInvocations(outsider);

        handler.handleTextMessage(nearby, new TextMessage(
                "{\"type\":\"signal\",\"targetPeerId\":\"peer-outsider\",\"payload\":{}}"));

        verify(outsider, never()).sendMessage(any(TextMessage.class));
    }

    @Test
    void unknownPublicAddressIsNeverTreatedAsSameNet() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        // 兜底地址不可辨识:两个 "unknown" 参与者即使地址字面相等也不构成同网。
        WebSocketSession first = session("session-1", "peer-1", "room-a", "room:42",
                "unknown", true, true);
        WebSocketSession second = session("session-2", "peer-2", "room-b", "room:42",
                "unknown", true, true);
        // 但同 group(roomId+roomKey)可见性不受兜底地址影响。
        WebSocketSession roomMate = session("session-3", "peer-3", "room-a", "room:42",
                "unknown", true, true);

        handler.afterConnectionEstablished(first);
        handler.afterConnectionEstablished(second);
        handler.afterConnectionEstablished(roomMate);

        assertEquals(Map.of("peer-1", true, "peer-3", true), peersById(lastRoster(first)));
        assertEquals(Map.of("peer-2", true), peersById(lastRoster(second)));

        // 定向信令同样不会跨房间投递给兜底地址对端。
        clearInvocations(second);
        handler.handleTextMessage(first, new TextMessage(
                "{\"type\":\"signal\",\"targetPeerId\":\"peer-2\",\"payload\":{}}"));
        verify(second, never()).sendMessage(any(TextMessage.class));
    }

    @Test
    void broadcastWithoutTargetStaysWithinGroup() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession source = session("session-1", "peer-source", "room-a", "public:203.0.113.10",
                "203.0.113.10", false, true);
        WebSocketSession sameGroup = session("session-2", "peer-same-group", "room-a",
                "public:203.0.113.10", "203.0.113.10", false, true);
        // 同网但不同房间:可见但收不到房间内广播。
        WebSocketSession sameNetOtherRoom = session("session-3", "peer-room", "room-a", "room:42",
                "203.0.113.10", true, true);

        handler.afterConnectionEstablished(source);
        handler.afterConnectionEstablished(sameGroup);
        handler.afterConnectionEstablished(sameNetOtherRoom);
        clearInvocations(sameGroup, sameNetOtherRoom);

        handler.handleTextMessage(source, new TextMessage("{\"type\":\"clipboard\",\"payload\":{}}"));

        var broadcast = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(sameGroup).sendMessage(broadcast.capture());
        assertEquals("clipboard",
                new ObjectMapper().readTree(broadcast.getValue().getPayload()).path("type").asText());
        verify(sameNetOtherRoom, never()).sendMessage(any(TextMessage.class));
    }

    @Test
    void hiddenPeerIsFilteredFromMergedRosterButStillReceivesRoster() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession hidden = session("session-1", "peer-hidden", "room-a", "room:42",
                "203.0.113.10", true, false);
        WebSocketSession visible = session("session-2", "peer-visible", "room-a", "room:42",
                "203.0.113.10", true, true);

        handler.afterConnectionEstablished(hidden);
        handler.afterConnectionEstablished(visible);

        assertEquals(Map.of("peer-visible", true), peersById(lastRoster(visible)));
        JsonNode hiddenRoster = lastRoster(hidden);
        assertNotNull(hiddenRoster);
        assertEquals(Map.of("peer-visible", true), peersById(hiddenRoster));
    }

    @Test
    void roomCapacityIsStillCountedPerGroup() throws Exception {
        PublicTransferProperties properties = new PublicTransferProperties();
        properties.setMaxDiscoveryPeersPerRoom(1);
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(properties);
        WebSocketSession first = session("session-1", "peer-1", "Alpha", "room-a", "room:42",
                "203.0.113.10", true, true);
        WebSocketSession sameGroupSecond = session("session-2", "peer-2", "Beta", "room-a", "room:42",
                "198.51.100.7", true, true);
        WebSocketSession sameNetOtherGroup = session("session-3", "peer-3", "Gamma", "room-a",
                "public:203.0.113.10", "203.0.113.10", false, true);

        handler.afterConnectionEstablished(first);
        handler.afterConnectionEstablished(sameGroupSecond);

        var errorMessage = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(sameGroupSecond).sendMessage(errorMessage.capture());
        JsonNode error = new ObjectMapper().readTree(errorMessage.getValue().getPayload());
        assertEquals("room is full", error.path("error").asText());
        verify(sameGroupSecond).close(CloseStatus.POLICY_VIOLATION);

        // 房间上限按 group 计算:同网其他房间的成员不受 room:42 满员影响。
        handler.afterConnectionEstablished(sameNetOtherGroup);
        verify(sameNetOtherGroup, never()).close(any(CloseStatus.class));
        assertTrue(peersById(lastRoster(sameNetOtherGroup)).containsKey("peer-1"));
    }

    @Test
    void hiddenParticipantIsSkippedByClusterPresenceRefresh() throws Exception {
        PublicTransferProperties properties = new PublicTransferProperties();
        properties.setClusterEnabled(true);
        PublicTransferCoordinationService coordination = mock(PublicTransferCoordinationService.class);
        when(coordination.enabled()).thenReturn(true);
        when(coordination.register(any(), anyInt()))
                .thenReturn(new PublicTransferCoordinationService.Registration(null, 1));
        when(coordination.refresh(any())).thenReturn(true);
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(properties, coordination);
        WebSocketSession hidden = session("session-hidden", "peer-hidden", "room-a", "room:42",
                "203.0.113.10", true, false);
        WebSocketSession visible = session("session-visible", "peer-visible", "room-a", "room:42",
                "203.0.113.10", true, true);

        handler.afterConnectionEstablished(hidden);
        handler.afterConnectionEstablished(visible);
        // 隐身端本就不注册共享 presence。
        verify(coordination, times(1)).register(any(), anyInt());
        clearInvocations(hidden, visible);

        handler.refreshClusterPresence();

        // refresh 只针对可见参与者调用一次;隐身端不续期、也不会因 refresh 失败被 dropLocal 踢掉。
        var refreshed = org.mockito.ArgumentCaptor.forClass(
                PublicTransferCoordinationService.Participant.class);
        verify(coordination).refresh(refreshed.capture());
        assertEquals("peer-visible", refreshed.getValue().peerId());
        verify(hidden, never()).close(any(CloseStatus.class));
        verify(visible, never()).close(any(CloseStatus.class));
    }

    @Test
    void viewerCannotRelayWhiteboardUpdates() throws Exception {
        PublicTransferDiscoveryWebSocketHandler handler =
                new PublicTransferDiscoveryWebSocketHandler(new PublicTransferProperties());
        WebSocketSession viewer = session(
                "session-viewer", "web-viewer", "web-viewer", "room-a", "room:42", "VIEWER");

        handler.afterConnectionEstablished(viewer);
        clearInvocations(viewer);
        handler.handleTextMessage(viewer, new TextMessage("{\"type\":\"whiteboard\",\"payload\":{}}"));

        var errorMessage = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(viewer).sendMessage(errorMessage.capture());
        JsonNode error = new ObjectMapper().readTree(errorMessage.getValue().getPayload());
        assertEquals("error", error.path("type").asText());
        assertEquals("viewer is read-only", error.path("error").asText());
    }

    private static JsonNode lastRoster(WebSocketSession session) throws Exception {
        var messages = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(session, atLeastOnce()).sendMessage(messages.capture());
        JsonNode roster = null;
        ObjectMapper mapper = new ObjectMapper();
        for (TextMessage message : messages.getAllValues()) {
            JsonNode node = mapper.readTree(message.getPayload());
            if ("roster".equals(node.path("type").asText())) {
                roster = node;
            }
        }
        return roster;
    }

    private static Map<String, Boolean> peersById(JsonNode roster) {
        assertNotNull(roster);
        Map<String, Boolean> peers = new HashMap<>();
        roster.path("peers").forEach(peer ->
                peers.put(peer.path("peerId").asText(), peer.path("sameRoom").asBoolean()));
        return peers;
    }

    private static WebSocketSession session(String sessionId, String peerId, String roomId, String roomKey) {
        return session(sessionId, peerId, peerId, roomId, roomKey);
    }

    private static WebSocketSession session(String sessionId, String peerId, String displayName,
                                            String roomId, String roomKey) {
        return session(sessionId, peerId, displayName, roomId, roomKey, "EDITOR");
    }

    private static WebSocketSession session(String sessionId, String peerId, String displayName,
                                            String roomId, String roomKey, String roomRole) {
        return session(sessionId, peerId, displayName, roomId, roomKey, roomRole,
                "203.0.113.10", true, true);
    }

    private static WebSocketSession session(String sessionId, String peerId, String roomId,
                                            String roomKey, String publicAddress,
                                            boolean sharedRoom, boolean discoverable) {
        return session(sessionId, peerId, peerId, roomId, roomKey,
                publicAddress, sharedRoom, discoverable);
    }

    private static WebSocketSession session(String sessionId, String peerId, String displayName,
                                            String roomId, String roomKey, String publicAddress,
                                            boolean sharedRoom, boolean discoverable) {
        return session(sessionId, peerId, displayName, roomId, roomKey, "EDITOR",
                publicAddress, sharedRoom, discoverable);
    }

    private static WebSocketSession session(String sessionId, String peerId, String displayName,
                                            String roomId, String roomKey, String roomRole,
                                            String publicAddress, boolean sharedRoom, boolean discoverable) {
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.getId()).thenReturn(sessionId);
        when(session.isOpen()).thenReturn(true);
        when(session.getAttributes()).thenReturn(Map.of(
                "peerId", peerId,
                "displayName", displayName,
                "roomId", roomId,
                "publicAddress", publicAddress,
                "roomKey", roomKey,
                "roomRole", roomRole,
                "sharedRoom", sharedRoom,
                "discoverable", discoverable
        ));
        return session;
    }
}
