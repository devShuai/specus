package com.theshuai.specusserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.config.PublicTransferProperties;
import org.junit.jupiter.api.Test;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

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

    private static WebSocketSession session(String sessionId, String peerId, String roomId, String roomKey) {
        return session(sessionId, peerId, peerId, roomId, roomKey);
    }

    private static WebSocketSession session(String sessionId, String peerId, String displayName,
                                            String roomId, String roomKey) {
        return session(sessionId, peerId, displayName, roomId, roomKey, "EDITOR");
    }

    private static WebSocketSession session(String sessionId, String peerId, String displayName,
                                            String roomId, String roomKey, String roomRole) {
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.getId()).thenReturn(sessionId);
        when(session.isOpen()).thenReturn(true);
        when(session.getAttributes()).thenReturn(Map.of(
                "peerId", peerId,
                "displayName", displayName,
                "roomId", roomId,
                "publicAddress", "203.0.113.10",
                "roomKey", roomKey,
                "roomRole", roomRole,
                "sharedRoom", true
        ));
        return session;
    }
}
