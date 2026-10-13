package com.theshuai.specusserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.management.service.ManagementAccessRevoked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Ends the management WebSockets of an account whose access changed (management-accounts.md 7.2):
 * its unused tickets go in the transaction that changes the account, and once that commits its
 * connections close here and, in a cluster, on every other instance through STCE kind 5
 * (public-transfer-cluster.md 5.2).
 */
@Component
public class ManagementAccessRevocations {
    private static final Logger log = LoggerFactory.getLogger(ManagementAccessRevocations.class);

    private final WebSocketTicketService tickets;
    private final ClientMessagesWebSocketHandler clientMessages;
    private final ConnectionEventsWebSocketHandler connectionEvents;
    private final PublicTransferCoordinationService coordination;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ManagementAccessRevocations(WebSocketTicketService tickets,
                                       ClientMessagesWebSocketHandler clientMessages,
                                       ConnectionEventsWebSocketHandler connectionEvents,
                                       PublicTransferCoordinationService coordination) {
        this.tickets = tickets;
        this.clientMessages = clientMessages;
        this.connectionEvents = connectionEvents;
        this.coordination = coordination;
        coordination.addListener(this::handleClusterEvent);
    }

    /** Still inside the account change's transaction: a rollback keeps the tickets. */
    @TransactionalEventListener(phase = TransactionPhase.BEFORE_COMMIT)
    public void revokeTickets(ManagementAccessRevoked revoked) {
        tickets.revokeIdentity(revoked.tenantId(), revoked.username());
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void closeConnections(ManagementAccessRevoked revoked) {
        String reason = revoked.reason().closeReason();
        closeLocal(revoked.tenantId(), revoked.username(), reason);
        if (!coordination.enabled()) {
            return;
        }
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("tenantId", revoked.tenantId());
        payload.put("username", revoked.username());
        payload.put("reason", revoked.reason().wireName());
        try {
            coordination.publishManagementRevocation(revoked.tenantId(), objectMapper.writeValueAsBytes(payload));
        } catch (Exception exception) {
            // The account change stands; the handshake check still refuses new connections.
            log.warn("publish management revocation failed; other instances keep their connections: {}",
                    exception.toString());
        }
    }

    void closeLocal(String tenantId, String username, String reason) {
        clientMessages.closeIdentity(tenantId, username, reason);
        connectionEvents.closeIdentity(tenantId, username, reason);
    }

    private void handleClusterEvent(PublicTransferClusterFrame.Event clusterEvent) {
        if (clusterEvent.kind() != PublicTransferClusterFrame.KIND_MANAGEMENT_REVOCATION) {
            return;
        }
        try {
            JsonNode payload = objectMapper.readTree(clusterEvent.payload());
            String tenantId = payload.path("tenantId").asText("");
            String username = payload.path("username").asText("");
            if (tenantId.isBlank() || username.isEmpty()
                    || !clusterEvent.groupId().equals(PublicTransferCoordinationService.managementGroupId(tenantId))) {
                log.warn("discarding management revocation cluster event with invalid identity binding");
                return;
            }
            closeLocal(tenantId, username,
                    ManagementAccessRevoked.Reason.closeReasonOf(payload.path("reason").asText("")));
        } catch (Exception exception) {
            log.warn("discarding invalid management revocation cluster event: {}", exception.getMessage());
        }
    }
}
