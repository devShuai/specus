package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.PeerMeshSession;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PeerMeshSessionRepository extends JpaRepository<PeerMeshSession, Long> {
    List<PeerMeshSession> findByTenantIdOrderByUpdatedAtDesc(String tenantId, Pageable pageable);

    List<PeerMeshSession> findByTenantIdAndStatusNotOrderByUpdatedAtDesc(String tenantId, String status);

    @Query("""
            select s from PeerMeshSession s
            where s.tenantId = :tenantId
              and s.status <> :closedStatus
              and (s.sourceClientId = :clientId or s.targetClientId = :clientId)
            order by s.updatedAt desc
            """)
    List<PeerMeshSession> findOpenByClientId(String tenantId, Long clientId, String closedStatus);

    List<PeerMeshSession> findByStatusNotAndExpiresAtLessThanEqualOrderByExpiresAtAsc(
            String status,
            String expiresAt,
            Pageable pageable);

    @Query("""
            select s from PeerMeshSession s
            where s.tenantId = :tenantId
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            order by s.updatedAt desc
            """)
    List<PeerMeshSession> findVisible(String tenantId, List<Long> clientIds, Pageable pageable);

    @Query("""
            select s from PeerMeshSession s
            where s.tenantId = :tenantId
              and s.status <> :closedStatus
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            order by s.updatedAt desc
            """)
    List<PeerMeshSession> findVisibleOpen(String tenantId, List<Long> clientIds, String closedStatus);
}
