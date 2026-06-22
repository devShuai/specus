package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.TrafficUsage;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TrafficUsageRepository extends JpaRepository<TrafficUsage, Long> {
    Optional<TrafficUsage> findByClientIdAndUsageDate(Long clientId, String usageDate);

    Optional<TrafficUsage> findByTenantIdAndClientIdAndUsageDate(String tenantId, Long clientId, String usageDate);

    List<TrafficUsage> findByClientId(Long clientId);

    List<TrafficUsage> findAllByOrderByUsageDateDescIdDesc(Pageable pageable);

    List<TrafficUsage> findByTenantIdOrderByUsageDateDescIdDesc(String tenantId, Pageable pageable);

    List<TrafficUsage> findByClientIdOrderByUsageDateDescIdDesc(Long clientId, Pageable pageable);

    List<TrafficUsage> findByTenantIdAndClientIdOrderByUsageDateDescIdDesc(String tenantId, Long clientId, Pageable pageable);

    /**
     * 按 clientId 聚合所有日子的上下行字节总量。用于客户端列表 / overview 的总览统计，
     * 避免 N+1（每个客户端一条 {@link #findByClientId(Long)} 查询）。
     */
    @Query("""
            select t.clientId as clientId,
                   sum(t.uploadBytes) as uploadBytes,
                   sum(t.downloadBytes) as downloadBytes
            from TrafficUsage t
            group by t.clientId
            """)
    List<TrafficTotal> sumBytesByClientId();

    /**
     * Same aggregation scoped to one tenant for the management UI.
     */
    @Query("""
            select t.clientId as clientId,
                   sum(t.uploadBytes) as uploadBytes,
                   sum(t.downloadBytes) as downloadBytes
            from TrafficUsage t
            where t.tenantId = :tenantId
            group by t.clientId
            """)
    List<TrafficTotal> sumBytesByTenantId(@Param("tenantId") String tenantId);

    /**
     * 单个客户端的上下行总量（聚合）。比 {@link #findByClientId(Long)} + stream sum 省 IO 与内存。
     */
    @Query("""
            select t.clientId as clientId,
                   sum(t.uploadBytes) as uploadBytes,
                   sum(t.downloadBytes) as downloadBytes
            from TrafficUsage t
            where t.clientId = :clientId
            group by t.clientId
            """)
    Optional<TrafficTotal> sumBytesByClientId(@Param("clientId") Long clientId);

    @Query("""
            select t.clientId as clientId,
                   sum(t.uploadBytes) as uploadBytes,
                   sum(t.downloadBytes) as downloadBytes
            from TrafficUsage t
            where t.tenantId = :tenantId and t.clientId = :clientId
            group by t.clientId
            """)
    Optional<TrafficTotal> sumBytesByTenantIdAndClientId(@Param("tenantId") String tenantId,
                                                         @Param("clientId") Long clientId);
}
