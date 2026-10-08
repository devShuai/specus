package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.SortableInstant;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

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
    @Transactional
    public Owned owned(String tenantId, String loginName) {
        return new Owned(
                count("select count(c) from ClientAccount c"
                        + " where c.tenantId = :tenantId and c.ownerUsername = :owner", tenantId, loginName),
                count("select count(c) from ClientCredential c"
                        + " where c.tenantId = :tenantId and c.ownerUsername = :owner", tenantId, loginName));
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
        update("""
                        delete from PeerMeshDevice d
                         where d.tenantId = :tenantId and d.ownerUsername = :owner
                           and not exists (select c.id from ClientAccount c where c.id = d.clientId)
                        """, tenantId, loginName);
        reassign("PeerMeshAcl", tenantId, loginName, actor);
        reassign("PeerMeshEgressPolicy", tenantId, loginName, actor);
    }

    private long count(String query, String tenantId, String owner) {
        return entityManager.createQuery(query, Long.class)
                .setParameter("tenantId", tenantId)
                .setParameter("owner", owner)
                .getSingleResult();
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
