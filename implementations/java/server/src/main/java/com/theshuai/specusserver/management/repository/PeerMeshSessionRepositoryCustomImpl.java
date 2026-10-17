package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshSession;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;
import java.util.Arrays;

@Transactional(propagation = Propagation.MANDATORY)
public class PeerMeshSessionRepositoryCustomImpl implements PeerMeshSessionRepositoryCustom {
    @PersistenceContext private EntityManager entities;
    @Override public Optional<Reference> findReference(long id) {
        var rows = entities.createNativeQuery("select id,tenant_id,source_client_id,target_client_id from peer_mesh_session where id=?1")
                .setParameter(1, id).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new Reference(number(row[0]), (String) row[1], number(row[2]), number(row[3])));
    }
    @Override public Optional<PeerMeshSession> lockCurrent(long id) {
        // SQLite must enter its writer before a read can be upgraded. Other providers use a
        // primary-key locking current read; no missing-pair range/gap-lock probe is introduced.
        entities.createNativeQuery("update peer_mesh_session set status=status where 1=0").executeUpdate();
        String lock = entities.unwrap(Session.class).doReturningWork(connection -> connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
        var rows = entities.createNativeQuery("""
                select id,tenant_id,source_client_id,source_client_name,target_client_id,target_client_name,
                       path_type,status,token_hash,started_at,updated_at,expires_at,closed_at,rtt_millis,
                       local_endpoint,remote_endpoint,direct_bytes,relay_bytes,last_traffic_at,last_keepalive_at
                  from peer_mesh_session where id=?1
                """ + lock).setParameter(1, id).getResultList();
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst(); var result = new PeerMeshSession();
        result.setId(number(row[0])); result.setTenantId((String) row[1]); result.setSourceClientId(number(row[2])); result.setSourceClientName((String) row[3]);
        result.setTargetClientId(number(row[4])); result.setTargetClientName((String) row[5]); result.setPathType((String) row[6]); result.setStatus((String) row[7]);
        result.setTokenHash((String) row[8]); result.setStartedAt((String) row[9]); result.setUpdatedAt((String) row[10]); result.setExpiresAt((String) row[11]);
        result.setClosedAt((String) row[12]); result.setRttMillis(row[13] == null ? null : number(row[13]));
        result.setLocalEndpoint((String) row[14]); result.setRemoteEndpoint((String) row[15]); result.setDirectBytes(number(row[16])); result.setRelayBytes(number(row[17]));
        result.setLastTrafficAt((String) row[18]); result.setLastKeepaliveAt((String) row[19]); return Optional.of(result);
    }
    @Override public PeerMeshSession saveCurrent(PeerMeshSession current) {
        entities.createNativeQuery("""
                update peer_mesh_session set path_type=?1,status=?2,updated_at=?3,closed_at=?4,rtt_millis=?5,
                       local_endpoint=?6,remote_endpoint=?7,direct_bytes=?8,relay_bytes=?9,last_traffic_at=?10,last_keepalive_at=?11
                 where id=?12 and tenant_id=?13
                """).setParameter(1,current.getPathType()).setParameter(2,current.getStatus()).setParameter(3,current.getUpdatedAt())
                .setParameter(4,current.getClosedAt()).setParameter(5,current.getRttMillis()).setParameter(6,current.getLocalEndpoint())
                .setParameter(7,current.getRemoteEndpoint()).setParameter(8,current.getDirectBytes()).setParameter(9,current.getRelayBytes())
                .setParameter(10,current.getLastTrafficAt()).setParameter(11,current.getLastKeepaliveAt())
                .setParameter(12,current.getId()).setParameter(13,current.getTenantId()).executeUpdate();
        var saved = lockCurrent(current.getId()).filter(row -> row.getTenantId().equals(current.getTenantId()))
                .orElseThrow(() -> new IllegalStateException("Peer session write postcondition failed"));
        // MySQL can legitimately report zero changed rows for a no-op. Compare material instead.
        if (!Arrays.equals(material(current), material(saved))) throw new IllegalStateException("Peer session write postcondition failed");
        return saved;
    }
    private static long number(Object value) { return ((Number) value).longValue(); }
    private static Object[] material(PeerMeshSession row) {
        return new Object[]{row.getPathType(),row.getStatus(),row.getUpdatedAt(),row.getClosedAt(),row.getRttMillis(),
                row.getLocalEndpoint(),row.getRemoteEndpoint(),row.getDirectBytes(),row.getRelayBytes(),row.getLastTrafficAt(),row.getLastKeepaliveAt()};
    }
}
