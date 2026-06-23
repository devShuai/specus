package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.PeerMeshSession;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PeerMeshSessionRepository extends JpaRepository<PeerMeshSession, Long> {
    List<PeerMeshSession> findByTenantIdOrderByUpdatedAtDesc(String tenantId, Pageable pageable);

    @Query("""
            select s from PeerMeshSession s
            where s.tenantId = :tenantId
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            order by s.updatedAt desc
            """)
    List<PeerMeshSession> findVisible(String tenantId, List<Long> clientIds, Pageable pageable);
}
