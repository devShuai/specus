package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshAcl;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Transactional(propagation = Propagation.MANDATORY)
public class PeerMeshAclRepositoryCustomImpl implements PeerMeshAclRepositoryCustom {
    @PersistenceContext private EntityManager entities;
    private static final String COLUMNS = "id,tenant_id,owner_username,source_client_id,source_client_name,"
            + "target_client_id,target_client_name,allowed,direction,created_at,updated_at";
    @Override public Optional<PeerMeshAcl> lockCurrent(Long id, String tenant) {
        return map(entities.createNativeQuery("select " + COLUMNS + " from peer_mesh_acl where id=?1 and tenant_id=?2" + rowLock())
                .setParameter(1, id).setParameter(2, tenant).getResultList(), tenant);
    }
    @Override public Optional<PeerMeshAcl> lockPair(String tenant, Long source, Long target) {
        return map(entities.createNativeQuery("select " + COLUMNS + " from peer_mesh_acl where tenant_id=?1 and source_client_id=?2 and target_client_id=?3" + rowLock())
                .setParameter(1, tenant).setParameter(2, source).setParameter(3, target).getResultList(), tenant);
    }
    @Override public PeerMeshAcl upsertCurrent(PeerMeshAcl requested, boolean updateDirection) {
        String product = entities.unwrap(Session.class).doReturningWork(connection -> connection.getMetaData().getDatabaseProductName());
        boolean mysql = product.toLowerCase(java.util.Locale.ROOT).contains("mysql") || product.toLowerCase(java.util.Locale.ROOT).contains("mariadb");
        // Parents serialize the same pair. Insert first: a locking missing-pair probe would
        // take InnoDB gap locks and can deadlock independent new pairs. Never use MySQL's ANY
        // duplicate-key UPDATE: a generated ID collision must not overwrite an unrelated ACL.
        entities.createNativeQuery((mysql ? "insert ignore" : "insert") + """
                 into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,
                  target_client_id,target_client_name,allowed,direction,created_at,updated_at)
                 values (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
                """ + (mysql ? "" : " on conflict do nothing"))
                .setParameter(1, requested.getId()).setParameter(2, requested.getTenantId()).setParameter(3, requested.getOwnerUsername())
                .setParameter(4, requested.getSourceClientId()).setParameter(5, requested.getSourceClientName())
                .setParameter(6, requested.getTargetClientId()).setParameter(7, requested.getTargetClientName())
                .setParameter(8, requested.isAllowed()).setParameter(9, requested.getDirection())
                .setParameter(10, requested.getCreatedAt()).setParameter(11, requested.getUpdatedAt()).executeUpdate();
        entities.createNativeQuery("""
                update peer_mesh_acl set owner_username=?1,source_client_name=?2,target_client_name=?3,
                 allowed=?4,direction=coalesce(?5,direction),updated_at=?6
                 where tenant_id=?7 and source_client_id=?8 and target_client_id=?9
                """).setParameter(1, requested.getOwnerUsername()).setParameter(2, requested.getSourceClientName())
                .setParameter(3, requested.getTargetClientName()).setParameter(4, requested.isAllowed())
                .setParameter(5, updateDirection ? requested.getDirection() : null).setParameter(6, requested.getUpdatedAt())
                .setParameter(7, requested.getTenantId()).setParameter(8, requested.getSourceClientId())
                .setParameter(9, requested.getTargetClientId()).executeUpdate();
        PeerMeshAcl current = lockPair(requested.getTenantId(), requested.getSourceClientId(), requested.getTargetClientId())
                .orElseThrow(() -> new IllegalStateException("ACL write postcondition failed"));
        if (!requested.getOwnerUsername().equals(current.getOwnerUsername()) || requested.isAllowed() != current.isAllowed()
                || !requested.getSourceClientName().equals(current.getSourceClientName())
                || !requested.getTargetClientName().equals(current.getTargetClientName())
                || !requested.getUpdatedAt().equals(current.getUpdatedAt())
                || updateDirection && !requested.getDirection().equals(current.getDirection()))
            throw new IllegalStateException("ACL write postcondition failed");
        return current;
    }
    @Override public void deleteCurrent(Long id, String tenant) {
        entities.createNativeQuery("delete from peer_mesh_acl where id=?1 and tenant_id=?2")
                .setParameter(1, id).setParameter(2, tenant).executeUpdate();
    }
    private String rowLock() {
        return entities.unwrap(Session.class).doReturningWork(connection -> connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
    }
    private static Optional<PeerMeshAcl> map(List<?> rows, String tenant) {
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst();
        if (!tenant.equals(row[1])) return Optional.empty();
        PeerMeshAcl acl = new PeerMeshAcl();
        acl.setId(((Number) row[0]).longValue()); acl.setTenantId((String) row[1]); acl.setOwnerUsername((String) row[2]);
        acl.setSourceClientId(((Number) row[3]).longValue()); acl.setSourceClientName((String) row[4]);
        acl.setTargetClientId(((Number) row[5]).longValue()); acl.setTargetClientName((String) row[6]);
        acl.setAllowed(row[7] instanceof Boolean value ? value : ((Number) row[7]).intValue() != 0);
        acl.setDirection((String) row[8]); acl.setCreatedAt((String) row[9]); acl.setUpdatedAt((String) row[10]);
        return Optional.of(acl);
    }
}
