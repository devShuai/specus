package com.theshuai.specusserver.management.service;

import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicy;
import com.theshuai.specusserver.management.model.PeerMeshSessionView;
import com.theshuai.specusserver.management.model.PeerMeshSharedService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/** Operational references disappear with a client; historical sessions and usage remain. */
@Component
public class ClientPeerReferences {
    @PersistenceContext private EntityManager entityManager;
    private final PeerMeshService peerMeshService;
    private final ApplicationEventPublisher events;

    public ClientPeerReferences(PeerMeshService peerMeshService, ApplicationEventPublisher events) {
        this.peerMeshService = peerMeshService;
        this.events = events;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void forgetClient(ClientAccount account) {
        String tenant = account.getTenantId();
        long id = account.getId();
        String now = Instant.now().toString();
        List<PeerMeshSessionView> closed = peerMeshService.closeOpenSessionsForClient(tenant, id);
        delete("PeerMeshAcl", "(r.sourceClientId = :id or r.targetClientId = :id)", tenant, id);
        delete("PeerMeshDevice", "r.clientId = :id", tenant, id);
        delete("PeerMeshEgressPolicy", "r.egressClientId = :id", tenant, id);
        delete("PeerMeshSharedService", "r.clientId = :id", tenant, id);

        for (PeerMeshEgressPolicy policy : entityManager.createQuery(
                "from PeerMeshEgressPolicy r where r.tenantId = :tenant", PeerMeshEgressPolicy.class)
                .setParameter("tenant", tenant).getResultList()) {
            List<Long> allowed = PeerServiceDiscovery.decodeClientIds(policy.getAllowedConsumerClientIds());
            if (allowed.contains(id)) {
                policy.setAllowedConsumerClientIds(PeerServiceDiscovery.encodeClientIds(
                        allowed.stream().filter(value -> value != id).toList()));
                policy.setUpdatedAt(now);
            }
        }
        for (PeerMeshSharedService service : entityManager.createQuery(
                "from PeerMeshSharedService r where r.tenantId = :tenant", PeerMeshSharedService.class)
                .setParameter("tenant", tenant).getResultList()) {
            List<Long> allowed = PeerServiceDiscovery.decodeClientIds(service.getAllowedClientIds());
            if (allowed.contains(id)) {
                List<Long> remaining = allowed.stream().filter(value -> value != id).toList();
                service.setAllowedClientIds(PeerServiceDiscovery.encodeClientIds(remaining));
                // Unlike egress, an empty shared-service allowlist means all eligible peers.
                // Removing the last explicit recipient must never widen that grant.
                if (remaining.isEmpty() && !PeerServiceDiscovery.VISIBILITY_OWNER.equals(service.getVisibility())) {
                    service.setEnabled(false);
                }
                service.setUpdatedAt(now);
            }
        }
        events.publishEvent(new Deleted(tenant, id, account.getClientName(), closed));
    }

    private void delete(String entity, String predicate, String tenant, long id) {
        entityManager.createQuery("delete from " + entity + " r where r.tenantId = :tenant and " + predicate)
                .setParameter("tenant", tenant).setParameter("id", id).executeUpdate();
    }

    public record Deleted(String tenantId, long clientId, String clientName,
                          List<PeerMeshSessionView> closedSessions) {
        public Deleted { closedSessions = List.copyOf(closedSessions); }
    }
}
