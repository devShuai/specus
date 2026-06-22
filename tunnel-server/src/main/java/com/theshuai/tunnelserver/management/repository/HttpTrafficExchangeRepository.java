package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface HttpTrafficExchangeRepository extends JpaRepository<HttpTrafficExchange, Long> {
    List<HttpTrafficExchange> findByTenantIdOrderByIdDesc(String tenantId, Pageable pageable);

    List<HttpTrafficExchange> findByTenantIdAndClientIdOrderByIdDesc(
            String tenantId, Long clientId, Pageable pageable);

    List<HttpTrafficExchange> findByTenantIdAndRouteOrderByIdDesc(
            String tenantId, String route, Pageable pageable);

    List<HttpTrafficExchange> findByTenantIdAndClientIdAndRouteOrderByIdDesc(
            String tenantId, Long clientId, String route, Pageable pageable);
}
