package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ConnectionRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ConnectionRecordRepository extends JpaRepository<ConnectionRecord, Long>,
        JpaSpecificationExecutor<ConnectionRecord> {
    List<ConnectionRecord> findAllByOrderByIdDesc(Pageable pageable);

    List<ConnectionRecord> findByClientIdOrderByIdDesc(Long clientId, Pageable pageable);

    long countBySuccess(boolean success);

    long countByTenantIdAndSuccess(String tenantId, boolean success);

    long countByTenantIdAndClientIdInAndSuccess(String tenantId, List<Long> clientIds, boolean success);

    long countByClientIdAndConnectedAtGreaterThanEqual(Long clientId, String connectedAt);

    long countByTenantIdAndClientIdAndConnectedAtGreaterThanEqual(String tenantId, Long clientId, String connectedAt);

    // Roll detail rows older than the cutoff into per-natural-month totals (month = yyyy-MM from
    // the ISO connectedAt).
    @Query("""
            select new com.theshuai.tunnelserver.management.repository.ConnectionStatRow(
                coalesce(r.tenantId, 'default'), max(r.clientId), r.clientName, substring(r.connectedAt, 1, 7),
                count(r), sum(case when r.success = true then 1L else 0L end))
            from ConnectionRecord r
            where r.connectedAt < :cutoff
            group by coalesce(r.tenantId, 'default'), r.clientName, substring(r.connectedAt, 1, 7)
            """)
    List<ConnectionStatRow> aggregateMonthlyBefore(@Param("cutoff") String cutoff);

    @Modifying
    @Query("delete from ConnectionRecord r where r.connectedAt < :cutoff")
    int deleteByConnectedAtBefore(@Param("cutoff") String cutoff);

    // 服务端进程被 kill / 重启时 channelInactive 不会触发，旧记录的 disconnectedAt 会留 null，
    // 让 UI 一直把它们算成"在线"。启动时统一把启动前还没收尾的记录关上。
    // cutoff 取启动时刻，避免误伤启动过程中刚进来的新连接。
    @Modifying
    @Query("update ConnectionRecord r set r.disconnectedAt = :cutoff, r.disconnectReason = :reason " +
            "where r.disconnectedAt is null and r.connectedAt < :cutoff")
    int closeOpenRecordsBefore(@Param("cutoff") String cutoff, @Param("reason") String reason);

    // 服务端优雅停机时（ContextClosedEvent）直接把所有还在线的记录收尾，
    // 避免 channelInactive → loginExecutor 异步派发链路在 shutdown 过程中被 RejectedExecution。
    @Modifying
    @Query("update ConnectionRecord r set r.disconnectedAt = :now, r.disconnectReason = :reason " +
            "where r.disconnectedAt is null")
    int markAllOpenAsClosed(@Param("now") String now, @Param("reason") String reason);
}
