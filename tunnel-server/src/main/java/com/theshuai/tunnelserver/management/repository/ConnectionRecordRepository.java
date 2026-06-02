package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ConnectionRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ConnectionRecordRepository extends JpaRepository<ConnectionRecord, Long> {
    List<ConnectionRecord> findAllByOrderByIdDesc(Pageable pageable);

    List<ConnectionRecord> findByClientIdOrderByIdDesc(Long clientId, Pageable pageable);

    long countBySuccess(boolean success);

    long countByClientIdAndConnectedAtGreaterThanEqual(Long clientId, String connectedAt);

    // Roll detail rows older than the cutoff into per-natural-month totals (month = yyyy-MM from
    // the ISO connectedAt).
    @Query("""
            select new com.theshuai.tunnelserver.management.repository.ConnectionStatRow(
                max(r.clientId), r.clientName, substring(r.connectedAt, 1, 7),
                count(r), sum(case when r.success = true then 1L else 0L end))
            from ConnectionRecord r
            where r.connectedAt < :cutoff
            group by r.clientName, substring(r.connectedAt, 1, 7)
            """)
    List<ConnectionStatRow> aggregateMonthlyBefore(@Param("cutoff") String cutoff);

    @Modifying
    @Query("delete from ConnectionRecord r where r.connectedAt < :cutoff")
    int deleteByConnectedAtBefore(@Param("cutoff") String cutoff);
}
