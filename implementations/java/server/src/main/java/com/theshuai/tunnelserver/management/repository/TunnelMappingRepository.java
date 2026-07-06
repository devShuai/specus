package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.TunnelMapping;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TunnelMappingRepository extends JpaRepository<TunnelMapping, Long> {
    List<TunnelMapping> findAllByOrderByIdDesc();

    List<TunnelMapping> findByTenantIdOrderByIdDesc(String tenantId);

    List<TunnelMapping> findByClientIdOrderByIdDesc(Long clientId);

    List<TunnelMapping> findByTenantIdAndClientIdOrderByIdDesc(String tenantId, Long clientId);

    List<TunnelMapping> findByTenantIdAndClientIdInOrderByIdDesc(String tenantId, List<Long> clientIds);

    List<TunnelMapping> findByClientIdAndEnabledTrueOrderByIdAsc(Long clientId);

    List<TunnelMapping> findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(String tenantId, Long clientId);

    Optional<TunnelMapping> findByListenPort(int listenPort);

    Optional<TunnelMapping> findByIdAndTenantId(Long id, String tenantId);
}
