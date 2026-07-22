package com.theshuai.tunnelserver.websocket;

import com.theshuai.tunnelserver.management.model.WebSocketTicket;
import com.theshuai.tunnelserver.management.repository.WebSocketTicketRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class WebSocketTicketServiceTests {
    @Test
    void ticketIsScopedAddressBoundAndConsumedOnce() {
        WebSocketTicketRepository repository = mock(WebSocketTicketRepository.class);
        WebSocketTicketService service = new WebSocketTicketService(repository);
        WebSocketTicketService.IssuedTicket issued = service.issue(
                WebSocketTicketService.Scope.PUBLIC_TRANSFER, Map.of("peerId", "peer-a"), "192.0.2.1");
        ArgumentCaptor<WebSocketTicket> saved = ArgumentCaptor.forClass(WebSocketTicket.class);
        verify(repository).save(saved.capture());
        when(repository.findById(saved.getValue().getTokenHash())).thenReturn(Optional.of(saved.getValue()));

        assertTrue(service.consume(WebSocketTicketService.Scope.CONNECTIONS,
                issued.ticket(), "192.0.2.1").isEmpty());
        assertTrue(service.consume(WebSocketTicketService.Scope.PUBLIC_TRANSFER,
                issued.ticket(), "192.0.2.2").isEmpty());
        verify(repository, never()).deleteById(anyString());

        when(repository.consume(anyString(), anyString(), anyString())).thenReturn(1, 0);
        assertEquals("peer-a", service.consume(WebSocketTicketService.Scope.PUBLIC_TRANSFER,
                issued.ticket(), "192.0.2.1").orElseThrow().get("peerId"));
        assertTrue(service.consume(WebSocketTicketService.Scope.PUBLIC_TRANSFER,
                issued.ticket(), "192.0.2.1").isEmpty());
    }
}
