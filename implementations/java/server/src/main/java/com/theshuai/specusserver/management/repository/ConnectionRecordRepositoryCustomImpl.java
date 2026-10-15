package com.theshuai.specusserver.management.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.theshuai.specusserver.management.model.ConnectionRecord;
import java.util.Optional;

@Transactional(propagation = Propagation.MANDATORY)
public class ConnectionRecordRepositoryCustomImpl implements ConnectionRecordRepositoryCustom {
    @PersistenceContext private EntityManager entities;
    @Override public Optional<ConnectionRecord> disconnectCurrent(long id, String now, String reason) {
        // The first statement reserves SQLite's writer; loading a JPA row first would create a
        // read snapshot that cannot be upgraded after another audit/login writer commits in WAL.
        int changed = entities.createNativeQuery("""
                update specus_connection_record
                   set disconnected_at=coalesce(disconnected_at,?1),disconnect_reason=coalesce(disconnect_reason,?2)
                 where id=?3 and (disconnected_at is null or disconnect_reason is null)
                """).setParameter(1,now).setParameter(2,reason).setParameter(3,id).executeUpdate();
        if (changed == 0) return Optional.empty();
        ConnectionRecord current=entities.find(ConnectionRecord.class,id);
        // A caller may already have this record in its persistence context. Don't publish a stale
        // pre-update view or clear unrelated managed state to obtain a current disconnect event.
        entities.refresh(current);
        return Optional.of(current);
    }

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
