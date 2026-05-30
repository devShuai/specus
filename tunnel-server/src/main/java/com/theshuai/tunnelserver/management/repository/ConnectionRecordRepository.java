package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ConnectionRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ConnectionRecordRepository extends JpaRepository<ConnectionRecord, Long> {
    List<ConnectionRecord> findAllByOrderByIdDesc(Pageable pageable);

    List<ConnectionRecord> findByClientIdOrderByIdDesc(Long clientId, Pageable pageable);

    long countBySuccess(boolean success);

    long countByClientIdAndConnectedAtGreaterThanEqual(Long clientId, String connectedAt);
}
