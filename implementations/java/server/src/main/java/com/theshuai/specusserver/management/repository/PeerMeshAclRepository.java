package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshAcl;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PeerMeshAclRepository extends JpaRepository<PeerMeshAcl, Long> {
    Optional<PeerMeshAcl> findByTenantIdAndSourceClientIdAndTargetClientId(String tenantId, Long sourceClientId, Long targetClientId);

    List<PeerMeshAcl> findByTenantIdOrderByIdDesc(String tenantId);

    List<PeerMeshAcl> findByTenantIdAndOwnerUsernameOrderByIdDesc(String tenantId, String ownerUsername);

    void deleteByTenantIdAndSourceClientIdAndTargetClientId(String tenantId, Long sourceClientId, Long targetClientId);
}
