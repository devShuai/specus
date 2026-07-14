package com.theshuai.tunnelserver.management.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;

/**
 * Keeps mutable client names in operational, denormalized records aligned with the account.
 * Historical connection and traffic-detail records intentionally retain the name seen at capture time.
 */
@Repository
public class ClientNameReferenceRepository {
    @PersistenceContext
    private EntityManager entityManager;

    public void rename(long clientId, String clientName, String updatedAt) {
        update("update ClientIdentity i set i.clientName = :clientName where i.clientId = :clientId",
                clientId, clientName);
        updateWithTimestamp("update TunnelMapping m set m.clientName = :clientName, m.updatedAt = :updatedAt where m.clientId = :clientId",
                clientId, clientName, updatedAt);
        updateWithTimestamp("update HttpRouteMapping r set r.clientName = :clientName, r.updatedAt = :updatedAt where r.clientId = :clientId",
                clientId, clientName, updatedAt);
        updateWithTimestamp("update PeerMeshDevice d set d.clientName = :clientName, d.updatedAt = :updatedAt where d.clientId = :clientId",
                clientId, clientName, updatedAt);
        updateWithTimestamp("update PeerMeshAcl a set a.sourceClientName = :clientName, a.updatedAt = :updatedAt where a.sourceClientId = :clientId",
                clientId, clientName, updatedAt);
        updateWithTimestamp("update PeerMeshAcl a set a.targetClientName = :clientName, a.updatedAt = :updatedAt where a.targetClientId = :clientId",
                clientId, clientName, updatedAt);
        update("update TrafficUsage u set u.clientName = :clientName where u.clientId = :clientId",
                clientId, clientName);
        update("update ResourceTrafficUsage u set u.clientName = :clientName where u.clientId = :clientId",
                clientId, clientName);
    }

    private void update(String query, long clientId, String clientName) {
        entityManager.createQuery(query)
                .setParameter("clientId", clientId)
                .setParameter("clientName", clientName)
                .executeUpdate();
    }

    private void updateWithTimestamp(String query, long clientId, String clientName, String updatedAt) {
        entityManager.createQuery(query)
                .setParameter("clientId", clientId)
                .setParameter("clientName", clientName)
                .setParameter("updatedAt", updatedAt)
                .executeUpdate();
    }
}
