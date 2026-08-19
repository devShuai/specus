package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshSharedService;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PeerMeshSharedServiceRepository extends JpaRepository<PeerMeshSharedService, Long> {
    List<PeerMeshSharedService> findByTenantIdOrderByClientNameAscNameAsc(String tenantId);

    List<PeerMeshSharedService> findByTenantIdAndClientIdOrderByNameAsc(String tenantId, Long clientId);

    List<PeerMeshSharedService> findByTenantIdAndClientIdInOrderByClientNameAscNameAsc(String tenantId,
                                                                                        List<Long> clientIds);

    Optional<PeerMeshSharedService> findByIdAndTenantId(Long id, String tenantId);

    Optional<PeerMeshSharedService> findByTenantIdAndClientIdAndServiceId(String tenantId,
                                                                          Long clientId,
                                                                          String serviceId);

    long countByTenantIdAndEnabledTrue(String tenantId);
}
