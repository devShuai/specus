package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientCredential;
import jakarta.persistence.EntityManager;
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
        var rows = entities.createNativeQuery("""
                select id, tenant_id, owner_username, api_key, secret_hash, enabled,
                       max_online_instances, created_at, updated_at
                  from specus_client_credential where id=?1 and tenant_id=?2
                """ + rowLock).setParameter(1, id).setParameter(2, tenantId).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        // Do not map a native entity or refresh an existing managed instance. Both can return
        // cached fields, and a plain refresh can read an older MySQL REPEATABLE READ snapshot
        // even after obtaining the row lock. These scalar fields come from the locking read.
        Object[] row = (Object[]) rows.getFirst();
        ClientCredential current = new ClientCredential();
        current.setId(((Number) row[0]).longValue());
        current.setTenantId((String) row[1]);
        current.setOwnerUsername((String) row[2]);
        current.setApiKey((String) row[3]);
        current.setSecretHash((String) row[4]);
        current.setEnabled(row[5] instanceof Boolean value ? value : ((Number) row[5]).intValue() != 0);
        current.setMaxOnlineInstances(((Number) row[6]).intValue());
        current.setCreatedAt((String) row[7]);
        current.setUpdatedAt((String) row[8]);
        return Optional.of(current);
    }
}
