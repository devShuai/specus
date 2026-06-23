package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ResourceTrafficUsage;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ResourceTrafficUsageRepository extends JpaRepository<ResourceTrafficUsage, Long> {
    Optional<ResourceTrafficUsage> findByTenantIdAndClientIdAndResourceTypeAndResourceKeyAndUsageDate(
            String tenantId, Long clientId, String resourceType, String resourceKey, String usageDate);

    List<ResourceTrafficUsage> findByTenantIdOrderByUsageDateDescIdDesc(String tenantId, Pageable pageable);

    List<ResourceTrafficUsage> findByTenantIdAndResourceTypeOrderByUsageDateDescIdDesc(
            String tenantId, String resourceType, Pageable pageable);

    List<ResourceTrafficUsage> findByTenantIdAndClientIdOrderByUsageDateDescIdDesc(
            String tenantId, Long clientId, Pageable pageable);

    List<ResourceTrafficUsage> findByTenantIdAndClientIdInOrderByUsageDateDescIdDesc(
            String tenantId, List<Long> clientIds, Pageable pageable);

    List<ResourceTrafficUsage> findByTenantIdAndClientIdAndResourceTypeOrderByUsageDateDescIdDesc(
            String tenantId, Long clientId, String resourceType, Pageable pageable);

    List<ResourceTrafficUsage> findByTenantIdAndClientIdInAndResourceTypeOrderByUsageDateDescIdDesc(
            String tenantId, List<Long> clientIds, String resourceType, Pageable pageable);
}
