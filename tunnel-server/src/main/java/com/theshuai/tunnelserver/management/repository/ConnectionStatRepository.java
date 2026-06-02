package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ConnectionStat;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ConnectionStatRepository extends JpaRepository<ConnectionStat, Long> {
    Optional<ConnectionStat> findByClientNameAndStatMonth(String clientName, String statMonth);

    List<ConnectionStat> findAllByOrderByStatMonthDescClientNameAsc(Pageable pageable);

    List<ConnectionStat> findByClientNameOrderByStatMonthDesc(String clientName, Pageable pageable);
}
