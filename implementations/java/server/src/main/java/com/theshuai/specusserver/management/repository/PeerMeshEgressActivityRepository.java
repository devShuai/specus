package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshEgressActivity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PeerMeshEgressActivityRepository extends JpaRepository<PeerMeshEgressActivity, Long> {
    List<PeerMeshEgressActivity> findByTenantIdOrderByEgressClientNameAsc(String tenantId);

    Optional<PeerMeshEgressActivity> findByTenantIdAndEgressClientId(String tenantId, Long egressClientId);
}
