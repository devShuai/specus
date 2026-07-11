package com.theshuai.tunnelserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.tunnelserver.config.PublicTransferProperties;
import org.junit.jupiter.api.Test;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PublicTransferDiscoveryWebSocketHandlerTests {

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
        PublicTransferDiscoveryWebSocketHandler handler = new PublicTransferDiscoveryWebSocketHandler(
                new PublicTransferProperties());
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

    private static WebSocketSession session(String sessionId, String peerId, String roomId, String roomKey) {
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.getId()).thenReturn(sessionId);
        when(session.isOpen()).thenReturn(true);
        when(session.getAttributes()).thenReturn(Map.of(
                "peerId", peerId,
                "displayName", peerId,
                "roomId", roomId,
                "publicAddress", "203.0.113.10",
                "roomKey", roomKey,
                "sharedRoom", true
        ));
        return session;
    }
}
