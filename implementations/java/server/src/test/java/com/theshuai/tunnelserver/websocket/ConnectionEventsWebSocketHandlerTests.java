package com.theshuai.tunnelserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.tunnelserver.management.model.ConnectionRecordView;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import org.junit.jupiter.api.Test;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConnectionEventsWebSocketHandlerTests {

    @Test
    void managementEventPublishesThroughClusterAndDeliversOnlyAfterRedisFanout() throws Exception {
        ClientAccountRepository repository = mock(ClientAccountRepository.class);
        PublicTransferCoordinationService coordination = mock(PublicTransferCoordinationService.class);
        AtomicReference<Consumer<PublicTransferClusterFrame.Event>> clusterListener =
                new AtomicReference<>();
        doAnswer(invocation -> {
            clusterListener.set(invocation.getArgument(0));
            return null;
        }).when(coordination).addListener(any());
        when(coordination.enabled()).thenReturn(true);

        ConnectionEventsWebSocketHandler handler =
                new ConnectionEventsWebSocketHandler(repository, coordination);
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.getId()).thenReturn("admin-session");
        when(session.isOpen()).thenReturn(true);
        when(session.getAttributes()).thenReturn(Map.of(
                WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID, "tenant-a",
                WebSocketTicketHandshakeInterceptor.ATTR_USER, "admin",
                WebSocketTicketHandshakeInterceptor.ATTR_ADMIN, true));
        handler.afterConnectionEstablished(session);

        ConnectionEvent event = new ConnectionEvent("tenant-a", "created",
                new ConnectionRecordView(7, 3L, "alpha", "channel", "203.0.113.10",
                        "2026-07-22T00:00:00Z", null, true, null, null, null));
        handler.broadcast("tenant-a", event);

        var payload = org.mockito.ArgumentCaptor.forClass(byte[].class);
        verify(coordination).publishManagement(eq("tenant-a"), payload.capture());
        verify(session, never()).sendMessage(any(TextMessage.class));

        clusterListener.get().accept(new PublicTransferClusterFrame.Event(
                PublicTransferClusterFrame.KIND_MANAGEMENT,
                false,
                0,
                PublicTransferCoordinationService.managementGroupId("tenant-a"),
                "",
                "",
                payload.getValue()));

        var message = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(session).sendMessage(message.capture());
        JsonNode delivered = new ObjectMapper().readTree(message.getValue().getPayload());
        assertEquals("tenant-a", delivered.path("tenantId").asText());
        assertEquals(7, delivered.path("connection").path("id").asInt());

        clearInvocations(session);
        clusterListener.get().accept(new PublicTransferClusterFrame.Event(
                PublicTransferClusterFrame.KIND_MANAGEMENT,
                false,
                0,
                PublicTransferCoordinationService.managementGroupId("tenant-b"),
                "",
                "",
                payload.getValue()));
        verify(session, never()).sendMessage(any(TextMessage.class));
    }

    @Test
    void managementEventFallsBackToLocalDeliveryWhenClusterPublishFails() throws Exception {
        ClientAccountRepository repository = mock(ClientAccountRepository.class);
        PublicTransferCoordinationService coordination = mock(PublicTransferCoordinationService.class);
        when(coordination.enabled()).thenReturn(true);
        org.mockito.Mockito.doThrow(new IllegalStateException("redis unavailable"))
                .when(coordination).publishManagement(eq("tenant-a"), any(byte[].class));
        ConnectionEventsWebSocketHandler handler =
                new ConnectionEventsWebSocketHandler(repository, coordination);
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.getId()).thenReturn("admin-session");
        when(session.isOpen()).thenReturn(true);
        when(session.getAttributes()).thenReturn(Map.of(
                WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID, "tenant-a",
                WebSocketTicketHandshakeInterceptor.ATTR_USER, "admin",
                WebSocketTicketHandshakeInterceptor.ATTR_ADMIN, true));
        handler.afterConnectionEstablished(session);

        handler.broadcast("tenant-a", new ConnectionEvent("tenant-a", "updated",
                new ConnectionRecordView(8, 4L, "beta", "channel", "203.0.113.11",
                        "2026-07-22T00:00:00Z", null, true, null, null, null)));

        var message = org.mockito.ArgumentCaptor.forClass(TextMessage.class);
        verify(session).sendMessage(message.capture());
        JsonNode delivered = new ObjectMapper().readTree(message.getValue().getPayload());
        assertEquals("updated", delivered.path("type").asText());
        assertEquals(8, delivered.path("connection").path("id").asInt());
    }
}
