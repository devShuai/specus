package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshEgressPolicy;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PeerMeshEgressPolicyRepository extends JpaRepository<PeerMeshEgressPolicy, Long> {
    List<PeerMeshEgressPolicy> findByTenantIdOrderByEgressClientNameAsc(String tenantId);

    List<PeerMeshEgressPolicy> findByTenantIdAndEnabledTrueOrderByEgressClientNameAsc(String tenantId);

    Optional<PeerMeshEgressPolicy> findByTenantIdAndEgressClientId(String tenantId, Long egressClientId);

    Optional<PeerMeshEgressPolicy> findByIdAndTenantId(Long id, String tenantId);
}
