package com.theshuai.tunnelserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.tunnelserver.config.PublicTransferProperties;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.Role;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.RoomAccess;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.WebSocketSession;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PublicTransferDiscoveryWebSocketHandlerTests {

    @Test
    void handshakeDecodesUtf8FormEncodedQueryValues() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        when(request.getURI()).thenReturn(URI.create(
                "ws://localhost/ws/public-transfer/discovery"
                        + "?roomId=%E6%B5%8B%E8%AF%95+room"
                        + "&peerId=web-123"
                        + "&displayName=%E7%BD%91%E9%A1%B5%E8%AE%BE%E5%A4%87+%C2%B7+6"
                        + "&roomToken=abc%2B123"));
        Map<String, Object> attributes = new HashMap<>();

        boolean accepted = new PublicTransferDiscoveryWebSocketHandler.PublicTransferDiscoveryHandshakeInterceptor()
                .beforeHandshake(
                        request,
                        mock(ServerHttpResponse.class),
                        mock(WebSocketHandler.class),
                        attributes);

        assertTrue(accepted);
        assertEquals("测试 room", attributes.get("roomId"));
        assertEquals("网页设备 · 6", attributes.get("displayName"));
        assertEquals("abc+123", attributes.get("roomToken"));
    }

    @Test
    void queryLimitDoesNotSplitUtf16SurrogatePair() {
        String prefix = "a".repeat(119);
        String value = prefix + "😀" + "z";

        assertEquals(prefix,
                PublicTransferDiscoveryWebSocketHandler.PublicTransferDiscoveryHandshakeInterceptor
                        .truncateUtf16WithoutSplittingSurrogate(value, 120));
        assertEquals(prefix + "😀",
                PublicTransferDiscoveryWebSocketHandler.PublicTransferDiscoveryHandshakeInterceptor
                        .truncateUtf16WithoutSplittingSurrogate(value, 121));
        assertEquals("short",
                PublicTransferDiscoveryWebSocketHandler.PublicTransferDiscoveryHandshakeInterceptor
                        .truncateUtf16WithoutSplittingSurrogate("short", 120));
    }

    @Test
    void duplicatePeerIdInSameGroupIsRejectedBeforeJoin() throws Exception {
        PublicTransferRoomService roomService = mock(PublicTransferRoomService.class);
        when(roomService.resolve(any(), any(), any())).thenReturn(new RoomAccess(42L, Role.OWNER, "room-a"));
        PublicTransferDiscoveryWebSocketHandler handler = new PublicTransferDiscoveryWebSocketHandler(
                new PublicTransferProperties(), roomService);
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
    void clientNameIsUniqueAcrossRoomsAndAvailabilityIsCaseInsensitive() throws Exception {
        PublicTransferRoomService roomService = mock(PublicTransferRoomService.class);
        when(roomService.resolve(any(), any(), any())).thenReturn(new RoomAccess(42L, Role.OWNER, "room-a"));
        PublicTransferDiscoveryWebSocketHandler handler = new PublicTransferDiscoveryWebSocketHandler(
                new PublicTransferProperties(), roomService);
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
    void viewerCannotRelayWhiteboardUpdates() throws Exception {
        PublicTransferRoomService roomService = mock(PublicTransferRoomService.class);
        when(roomService.resolve(any(), any(), any())).thenReturn(new RoomAccess(42L, Role.VIEWER, "room-a"));
        PublicTransferDiscoveryWebSocketHandler handler = new PublicTransferDiscoveryWebSocketHandler(
                new PublicTransferProperties(), roomService);
        WebSocketSession viewer = session("session-viewer", "web-viewer", "room-a", "token:room-a");

        handler.afterConnectionEstablished(viewer);
        clearInvocations(viewer);
        handler.handleTextMessage(viewer, new TextMessage("{\"type\":\"whiteboard\",\"payload\":{}}"));

        var errorMessage = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(viewer).sendMessage(errorMessage.capture());
        JsonNode error = new ObjectMapper().readTree(errorMessage.getValue().getPayload());
        assertEquals("error", error.path("type").asText());
        assertEquals("viewer is read-only", error.path("error").asText());
    }

    private static WebSocketSession session(String sessionId, String peerId, String roomId, String roomKey) {
        return session(sessionId, peerId, peerId, roomId, roomKey);
    }

    private static WebSocketSession session(String sessionId, String peerId, String displayName,
                                            String roomId, String roomKey) {
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.getId()).thenReturn(sessionId);
        when(session.isOpen()).thenReturn(true);
        when(session.getAttributes()).thenReturn(Map.of(
                "peerId", peerId,
                "displayName", displayName,
                "roomId", roomId,
                "publicAddress", "203.0.113.10",
                "roomKey", roomKey,
                "roomToken", "owner-token",
                "sharedRoom", true
        ));
        return session;
    }
}
