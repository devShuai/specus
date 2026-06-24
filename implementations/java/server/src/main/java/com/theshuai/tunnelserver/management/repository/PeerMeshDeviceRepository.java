package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.PeerMeshDevice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PeerMeshDeviceRepository extends JpaRepository<PeerMeshDevice, Long> {
    Optional<PeerMeshDevice> findByTenantIdAndClientId(String tenantId, Long clientId);

    Optional<PeerMeshDevice> findByTenantIdAndVirtualIp(String tenantId, String virtualIp);

    List<PeerMeshDevice> findByTenantIdOrderByClientNameAsc(String tenantId);

    List<PeerMeshDevice> findByTenantIdAndOwnerUsernameOrderByClientNameAsc(String tenantId, String ownerUsername);

    List<PeerMeshDevice> findByTenantIdAndOwnerUsernameAndEnabledTrueOrderByClientNameAsc(String tenantId, String ownerUsername);
}
