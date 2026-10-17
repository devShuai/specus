package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.SortableInstant;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
import org.hibernate.Session;

import java.time.Instant;

/**
 * The data an account's identity owns besides its account row (protocol/spec/management-accounts.md
 * section 7.1). Rows record their owner by tenant and login name, and a login name can be taken again
 * once the account is gone, so deleting an account must deal with them: otherwise a later account of
 * the same name would own them. Called inside the account deletion's transaction.
 */
@Component
public class AccountOwnedData {
    @PersistenceContext
    private EntityManager entityManager;

    /** The clients and access credentials an account still owns: while any remain it is not deleted. */
    @Transactional(propagation = Propagation.MANDATORY)
    public Owned owned(String tenantId, String loginName) {
        // Caller holds the immutable target account row: no new owned resources can be created.
        // COUNT under MySQL RR can still see an older snapshot established before that row lock.
        // Use current locking reads (PG forbids FOR UPDATE on aggregate COUNT). Credentials first,
        // then clients, matching authentication and the resource writers' lock order.
        long credentials = countCurrent("specus_client_credential", tenantId, loginName);
        long clients = countCurrent("specus_client_account", tenantId, loginName);
        return new Owned(clients, credentials);
    }

    /**
     * Deletes the identity's personal data and hands its tenant policies to the acting administrator.
     * Diagram documents, download grants and download usage go. Attachments expire at {@code now}, so
     * nothing can complete, download or count them any more, and the expiry scan deletes their objects
     * (the row is the only record of the object, so it stays until then). Peer device rows of clients
     * that no longer exist go. Peer ACLs and egress policies decide how other people's clients connect:
     * they stay, owned by {@code actor} from now on.
     */
    @Transactional
    public void forget(String tenantId, String loginName, String actor, Instant now) {
        update("delete from UserDiagramDocument d where d.tenantId = :tenantId and d.ownerUsername = :owner",
                tenantId, loginName);
        String cutoff = SortableInstant.format(now);
        entityManager.createQuery("""
                        update TransferAttachment a
                           set a.expiresAt = :cutoff, a.uploadExpiresAt = :cutoff, a.updatedAt = :updatedAt
                         where a.tenantId = :tenantId and a.ownerUsername = :owner
                           and a.status <> :expired and a.expiresAt > :cutoff
                        """)
                .setParameter("cutoff", cutoff)
                .setParameter("updatedAt", now.toString())
                .setParameter("tenantId", tenantId)
                .setParameter("owner", loginName)
                .setParameter("expired", TransferAttachmentService.STATUS_EXPIRED)
                .executeUpdate();
        update("delete from TransferAttachmentDownloadGrant g where g.tenantId = :tenantId and g.username = :owner",
                tenantId, loginName);
        update("delete from TransferAttachmentDownloadUsage u where u.tenantId = :tenantId and u.username = :owner",
                tenantId, loginName);
        // The subquery reads a different table: no MySQL target-table wrapper is needed.
        // Hibernate's MySQLDialect adds a derived table around this correlated JPQL delete,
        // which MariaDB rejects because the outer alias is not visible inside that wrapper.
        entityManager.createNativeQuery("""
                delete from peer_mesh_device where tenant_id=?1 and owner_username=?2
                  and not exists (select 1 from specus_client_account c where c.id=peer_mesh_device.client_id)
                """).setParameter(1, tenantId).setParameter(2, loginName).executeUpdate();
        reassign("PeerMeshAcl", tenantId, loginName, actor);
        reassign("PeerMeshEgressPolicy", tenantId, loginName, actor);
    }

    private long countCurrent(String table, String tenantId, String owner) {
        String lock = entityManager.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
        return entityManager.createNativeQuery("select id from " + table
                        + " where tenant_id=?1 and owner_username=?2 order by id" + lock)
                .setParameter(1, tenantId).setParameter(2, owner).getResultList().size();
    }

    private void update(String query, String tenantId, String owner) {
        entityManager.createQuery(query)
                .setParameter("tenantId", tenantId)
                .setParameter("owner", owner)
                .executeUpdate();
    }

    private void reassign(String entity, String tenantId, String owner, String actor) {
        entityManager.createQuery("update " + entity + " p set p.ownerUsername = :actor"
                        + " where p.tenantId = :tenantId and p.ownerUsername = :owner")
                .setParameter("actor", actor)
                .setParameter("tenantId", tenantId)
                .setParameter("owner", owner)
                .executeUpdate();
    }

    /** What an account still owns that must be deleted or handed over before the account can go. */
    public record Owned(long clients, long credentials) {
        public boolean any() {
            return clients > 0 || credentials > 0;
        }
    }
}
