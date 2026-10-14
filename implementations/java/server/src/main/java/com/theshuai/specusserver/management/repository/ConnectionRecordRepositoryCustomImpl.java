package com.theshuai.specusserver.management.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Transactional(propagation = Propagation.MANDATORY)
public class ConnectionRecordRepositoryCustomImpl implements ConnectionRecordRepositoryCustom {
    @PersistenceContext private EntityManager entities;
    @Override public long countCurrentConnections(String tenant, Long clientId, String since) {
        String lock = entities.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
        var rows = entities.createNativeQuery("""
                select id,tenant_id from specus_connection_record
                 where tenant_id=?1 and client_id=?2 and connected_at>=?3 order by id
                """ + lock).setParameter(1, tenant).setParameter(2, clientId).setParameter(3, since).getResultList();
        return rows.stream().filter(row -> tenant.equals(((Object[]) row)[1])).count();
    }
}
