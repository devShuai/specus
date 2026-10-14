package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientCredential;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityNotFoundException;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;

public class ClientCredentialRepositoryCustomImpl implements ClientCredentialRepositoryCustom {
    @PersistenceContext private EntityManager entities;

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<ClientCredential> lockCurrent(Long id, String tenantId) {
        // SQLite ignores SELECT FOR UPDATE. Make the FIRST statement a write so it obtains
        // the database writer reservation before any snapshot read, on the same JPA connection.
        // Do not depend on the affected-row count: MySQL may report zero for an unchanged row.
        entities.createNativeQuery("update specus_client_credential set enabled=enabled where id=?1 and tenant_id=?2")
                .setParameter(1, id).setParameter(2, tenantId).executeUpdate();
        // Use the database's plain FOR UPDATE, not Hibernate's alias-qualified form: MySQLDialect
        // against MariaDB can generate unsupported "FOR UPDATE OF alias". SQLite needs no such
        // clause because the first write already holds its writer reservation.
        String rowLock = entities.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
        if (entities.createNativeQuery("select id from specus_client_credential where id=?1 and tenant_id=?2" + rowLock)
                .setParameter(1, id).setParameter(2, tenantId).getResultList().isEmpty()) {
            return Optional.empty();
        }
        ClientCredential current = entities.find(ClientCredential.class, id);
        if (current == null) return Optional.empty();
        try {
            // Querying again alone can return a stale first-level-cache entity. Refresh it
            // explicitly. The native row lock also covers newly inserted rows on row-locking DBs.
            entities.refresh(current);
        } catch (EntityNotFoundException disappeared) {
            return Optional.empty();
        }
        return tenantId.equals(current.getTenantId()) ? Optional.of(current) : Optional.empty();
    }
}
