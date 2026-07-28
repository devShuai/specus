package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.HttpTrafficExchange;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.List;
import java.util.Optional;

public interface HttpTrafficExchangeRepository
        extends JpaRepository<HttpTrafficExchange, Long>, JpaSpecificationExecutor<HttpTrafficExchange> {
    Optional<HttpTrafficExchange> findByTenantIdAndId(String tenantId, Long id);

    Optional<HttpTrafficExchange> findByTenantIdAndIdAndClientIdIn(
            String tenantId, Long id, List<Long> clientIds);

    List<HttpTrafficExchange> findByTenantIdOrderByIdDesc(String tenantId, Pageable pageable);

    List<HttpTrafficExchange> findByTenantIdAndClientIdOrderByIdDesc(
            String tenantId, Long clientId, Pageable pageable);

    List<HttpTrafficExchange> findByTenantIdAndRouteOrderByIdDesc(
            String tenantId, String route, Pageable pageable);

    List<HttpTrafficExchange> findByTenantIdAndClientIdAndRouteOrderByIdDesc(
            String tenantId, Long clientId, String route, Pageable pageable);
}
