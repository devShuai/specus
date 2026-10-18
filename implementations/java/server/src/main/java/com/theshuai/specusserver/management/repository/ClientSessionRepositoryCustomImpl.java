package com.theshuai.specusserver.management.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Transactional(propagation = Propagation.MANDATORY)
public class ClientSessionRepositoryCustomImpl implements ClientSessionRepositoryCustom {
    private static final String COLUMNS = "id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,"
            + "machine_fingerprint,os_user,status,expires_at,channel_id,netty_connected_at";
    @PersistenceContext private EntityManager entities;

    @Override public Optional<SessionSnapshot> lockCurrent(Long id, String tenant) {
        entities.createNativeQuery("update specus_client_session set status=status where id=?1 and tenant_id=?2")
                .setParameter(1, id).setParameter(2, tenant).executeUpdate();
        var rows = entities.createNativeQuery("select " + COLUMNS + " from specus_client_session where id=?1 and tenant_id=?2" + rowLock())
                .setParameter(1, id).setParameter(2, tenant).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        SessionSnapshot current = snapshot((Object[]) rows.getFirst());
        return tenant.equals(current.tenantId()) ? Optional.of(current) : Optional.empty();
    }

    @Override public List<SessionSnapshot> lockOnline(Long credentialId, String tenant) {
        // Current locking rows, not COUNT in an earlier MySQL RR snapshot. Credential admissions
        // are serialized first. Keep session lock order deterministic within that credential.
        List<?> rows = entities.createNativeQuery("select " + COLUMNS + " from specus_client_session"
                        + " where credential_id=?1 and tenant_id=?2 and status='NETTY_ONLINE' order by id" + rowLock())
                .setParameter(1, credentialId).setParameter(2, tenant).getResultList();
        return rows.stream().map(row -> snapshot((Object[]) row)).filter(row -> tenant.equals(row.tenantId())).toList();
    }

    @Override public void markOnline(SessionSnapshot session, String name, String channel, String address, String now) {
        entities.createNativeQuery("""
                update specus_client_session set status='NETTY_ONLINE',client_name=?1,netty_connected_at=?2,
                       disconnected_at=null,channel_id=?3,remote_address=?4 where id=?5 and tenant_id=?6
                """).setParameter(1, name).setParameter(2, now).setParameter(3, channel).setParameter(4, address)
                .setParameter(5, session.id()).setParameter(6, session.tenantId()).executeUpdate();
    }

    @Override public void markDisconnected(SessionSnapshot session, String now) {
        entities.createNativeQuery("update specus_client_session set status='DISCONNECTED',disconnected_at=?1 where id=?2 and tenant_id=?3")
                .setParameter(1, now).setParameter(2, session.id()).setParameter(3, session.tenantId()).executeUpdate();
    }

    @Override public int disconnectChannel(Long id, String channel, String now) {
        // Atomic channel fencing: a delayed old-channel close cannot disconnect a newer binding
        // of the same still-valid token. Do not load/save a stale full session entity.
        return entities.createNativeQuery("""
                update specus_client_session set status='DISCONNECTED',disconnected_at=?1
                 where id=?2 and channel_id=?3 and status='NETTY_ONLINE'
                """).setParameter(1, now).setParameter(2, id).setParameter(3, channel).executeUpdate();
    }

    private String rowLock() {
        return entities.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
    }

    private static Long number(Object value) { return value == null ? null : ((Number) value).longValue(); }
    private static SessionSnapshot snapshot(Object[] row) {
        return new SessionSnapshot(number(row[0]), (String) row[1], number(row[2]), number(row[3]), number(row[4]),
                (String) row[5], (String) row[6], (String) row[7], (String) row[8], (String) row[9],
                (String) row[10], (String) row[11], (String) row[12]);
    }
}
