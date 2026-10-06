package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.HttpRouteMapping;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface HttpRouteMappingRepository extends JpaRepository<HttpRouteMapping, Long> {
    List<HttpRouteMapping> findAllByOrderByIdDesc();

    List<HttpRouteMapping> findByTenantIdOrderByIdDesc(String tenantId);

    List<HttpRouteMapping> findByClientIdOrderByIdDesc(Long clientId);

    List<HttpRouteMapping> findByTenantIdAndClientIdOrderByIdDesc(String tenantId, Long clientId);

    List<HttpRouteMapping> findByTenantIdAndClientIdInOrderByIdDesc(String tenantId, List<Long> clientIds);

    /**
     * 用于下发：仅取启用项，按 id 升序保证客户端面板呈现稳定。
     */
    List<HttpRouteMapping> findByClientIdAndEnabledTrueOrderByIdAsc(Long clientId);

    List<HttpRouteMapping> findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(String tenantId, Long clientId);

    Optional<HttpRouteMapping> findByClientIdAndRoute(Long clientId, String route);

    Optional<HttpRouteMapping> findByTenantIdAndClientIdAndRoute(String tenantId, Long clientId, String route);

    Optional<HttpRouteMapping> findByIdAndTenantId(Long id, String tenantId);

    boolean existsByClientId(Long clientId);
}
