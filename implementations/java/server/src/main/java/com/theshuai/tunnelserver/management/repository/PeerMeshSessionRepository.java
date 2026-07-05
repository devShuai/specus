package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.PeerMeshSession;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PeerMeshSessionRepository extends JpaRepository<PeerMeshSession, Long> {
    Page<PeerMeshSession> findByTenantIdOrderByUpdatedAtDesc(String tenantId, Pageable pageable);

    Page<PeerMeshSession> findByTenantIdAndStatusNotOrderByUpdatedAtDesc(String tenantId, String status, Pageable pageable);

    List<PeerMeshSession> findByTenantIdAndStatusNotOrderByUpdatedAtDesc(String tenantId, String status);

    @Query("""
            select s from PeerMeshSession s
            where s.tenantId = :tenantId
              and s.status <> :closedStatus
              and (s.sourceClientId = :clientId or s.targetClientId = :clientId)
            order by s.updatedAt desc
            """)
    List<PeerMeshSession> findOpenByClientId(String tenantId, Long clientId, String closedStatus);

    @Query("""
            select s from PeerMeshSession s
            where s.tenantId = :tenantId
              and s.status <> :closedStatus
              and (
                (s.sourceClientId = :sourceClientId and s.targetClientId = :targetClientId)
                or (s.sourceClientId = :targetClientId and s.targetClientId = :sourceClientId)
              )
            order by s.updatedAt desc
            """)
    List<PeerMeshSession> findOpenBetweenClients(
            String tenantId,
            Long sourceClientId,
            Long targetClientId,
            String closedStatus);

    List<PeerMeshSession> findByStatusNotAndExpiresAtLessThanEqualOrderByExpiresAtAsc(
            String status,
            String expiresAt,
            Pageable pageable);

    @Query(
            value = """
            select s from PeerMeshSession s
            where s.tenantId = :tenantId
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            order by s.updatedAt desc
            """,
            countQuery = """
            select count(s) from PeerMeshSession s
            where s.tenantId = :tenantId
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            """)
    Page<PeerMeshSession> findVisible(String tenantId, List<Long> clientIds, Pageable pageable);

    @Query("""
            select s from PeerMeshSession s
            where s.tenantId = :tenantId
              and s.status <> :closedStatus
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            order by s.updatedAt desc
            """)
    List<PeerMeshSession> findVisibleOpen(String tenantId, List<Long> clientIds, String closedStatus);

    @Query(
            value = """
            select s from PeerMeshSession s
            where s.tenantId = :tenantId
              and s.status <> :closedStatus
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            order by s.updatedAt desc
            """,
            countQuery = """
            select count(s) from PeerMeshSession s
            where s.tenantId = :tenantId
              and s.status <> :closedStatus
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            """)
    Page<PeerMeshSession> findVisibleOpenPage(String tenantId, List<Long> clientIds, String closedStatus, Pageable pageable);

    /**
     * 打洞/路径统计投影。reportedSessions = rttMillis 非空的会话数——rtt 只由客户端
     * PATH_REPORT 写入，因此非空即「至少确立过一次路径」；纯 NEGOTIATING 超时关闭的
     * 会话不计入，避免 createSession 默认 pathType=DIRECT 虚高直连占比。
     */
    interface PathTypeAggregate {
        String getPathType();

        String getStatus();

        long getSessions();

        long getReportedSessions();

        Double getAvgRttMillis();

        long getDirectBytes();

        long getRelayBytes();
    }

    @Query("""
            select s.pathType as pathType, s.status as status,
                   count(s) as sessions, count(s.rttMillis) as reportedSessions,
                   avg(s.rttMillis) as avgRttMillis,
                   coalesce(sum(s.directBytes), 0) as directBytes,
                   coalesce(sum(s.relayBytes), 0) as relayBytes
            from PeerMeshSession s
            where s.tenantId = :tenantId
            group by s.pathType, s.status
            """)
    List<PathTypeAggregate> aggregatePathTypes(String tenantId);

    @Query("""
            select s.pathType as pathType, s.status as status,
                   count(s) as sessions, count(s.rttMillis) as reportedSessions,
                   avg(s.rttMillis) as avgRttMillis,
                   coalesce(sum(s.directBytes), 0) as directBytes,
                   coalesce(sum(s.relayBytes), 0) as relayBytes
            from PeerMeshSession s
            where s.tenantId = :tenantId
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            group by s.pathType, s.status
            """)
    List<PathTypeAggregate> aggregateVisiblePathTypes(String tenantId, List<Long> clientIds);
}
