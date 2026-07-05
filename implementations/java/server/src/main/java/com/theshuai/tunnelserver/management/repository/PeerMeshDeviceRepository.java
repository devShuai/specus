package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.PeerMeshDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface PeerMeshDeviceRepository extends JpaRepository<PeerMeshDevice, Long> {
    Optional<PeerMeshDevice> findByTenantIdAndClientId(String tenantId, Long clientId);

    Optional<PeerMeshDevice> findByTenantIdAndVirtualIp(String tenantId, String virtualIp);

    List<PeerMeshDevice> findByTenantIdOrderByClientNameAsc(String tenantId);

    List<PeerMeshDevice> findByTenantIdAndOwnerUsernameOrderByClientNameAsc(String tenantId, String ownerUsername);

    List<PeerMeshDevice> findByTenantIdAndOwnerUsernameAndEnabledTrueOrderByClientNameAsc(String tenantId, String ownerUsername);

    interface NatTypeAggregate {
        String getNatType();

        long getDevices();
    }

    @Query("""
            select d.natType as natType, count(d) as devices
            from PeerMeshDevice d
            where d.tenantId = :tenantId
            group by d.natType
            """)
    List<NatTypeAggregate> aggregateNatTypes(String tenantId);

    @Query("""
            select d.natType as natType, count(d) as devices
            from PeerMeshDevice d
            where d.tenantId = :tenantId
              and d.ownerUsername = :ownerUsername
            group by d.natType
            """)
    List<NatTypeAggregate> aggregateNatTypesByOwner(String tenantId, String ownerUsername);
}
