package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.TrafficUsage;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TrafficUsageRepository extends JpaRepository<TrafficUsage, Long> {
    Optional<TrafficUsage> findByClientIdAndUsageDate(Long clientId, String usageDate);

    List<TrafficUsage> findByClientId(Long clientId);

    List<TrafficUsage> findAllByOrderByUsageDateDescIdDesc(Pageable pageable);

    List<TrafficUsage> findByClientIdOrderByUsageDateDescIdDesc(Long clientId, Pageable pageable);
}
