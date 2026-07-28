package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.SpecusMapping;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SpecusMappingRepository extends JpaRepository<SpecusMapping, Long> {
    List<SpecusMapping> findAllByOrderByIdDesc();

    List<SpecusMapping> findByTenantIdOrderByIdDesc(String tenantId);

    List<SpecusMapping> findByClientIdOrderByIdDesc(Long clientId);

    List<SpecusMapping> findByTenantIdAndClientIdOrderByIdDesc(String tenantId, Long clientId);

    List<SpecusMapping> findByTenantIdAndClientIdInOrderByIdDesc(String tenantId, List<Long> clientIds);

    List<SpecusMapping> findByClientIdAndEnabledTrueOrderByIdAsc(Long clientId);

    List<SpecusMapping> findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(String tenantId, Long clientId);

    Optional<SpecusMapping> findByListenPort(int listenPort);

    Optional<SpecusMapping> findByIdAndTenantId(Long id, String tenantId);
}
