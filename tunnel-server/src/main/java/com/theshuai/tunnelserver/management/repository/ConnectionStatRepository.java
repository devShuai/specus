package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ConnectionStat;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ConnectionStatRepository extends JpaRepository<ConnectionStat, Long> {
    Optional<ConnectionStat> findByClientNameAndStatMonth(String clientName, String statMonth);

    Optional<ConnectionStat> findByTenantIdAndClientNameAndStatMonth(String tenantId, String clientName, String statMonth);

    List<ConnectionStat> findAllByOrderByStatMonthDescClientNameAsc(Pageable pageable);

    List<ConnectionStat> findByTenantIdOrderByStatMonthDescClientNameAsc(String tenantId, Pageable pageable);

    List<ConnectionStat> findByClientNameOrderByStatMonthDesc(String clientName, Pageable pageable);

    List<ConnectionStat> findByTenantIdAndClientNameOrderByStatMonthDesc(String tenantId, String clientName, Pageable pageable);

    List<ConnectionStat> findByTenantIdAndClientIdInOrderByStatMonthDescClientNameAsc(
            String tenantId, List<Long> clientIds, Pageable pageable);

    List<ConnectionStat> findByTenantIdAndClientIdInAndClientNameOrderByStatMonthDesc(
            String tenantId, List<Long> clientIds, String clientName, Pageable pageable);
}
