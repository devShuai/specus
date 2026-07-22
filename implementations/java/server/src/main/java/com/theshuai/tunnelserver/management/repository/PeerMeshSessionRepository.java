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
     * 打洞/路径统计投影。pathType 使用「有效业务路径」：有业务流量时按 direct/relay
     * 字节占优方归类，没业务流量时才使用 PATH_REPORT 写入的探测路径。reportedSessions =
     * rttMillis 非空的会话数，表示至少确立过一次路径。
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

    interface AddressFamilyAggregate {
        String getAddressFamily();

        String getStatus();

        String getPathType();

        long getSessions();

        long getReportedSessions();
    }

    @Query("""
            select case
                     when s.relayBytes > s.directBytes then 'RELAY'
                     when s.directBytes > s.relayBytes then 'DIRECT'
                     else s.pathType
                   end as pathType,
                   s.status as status,
                   count(s) as sessions, count(s.rttMillis) as reportedSessions,
                   avg(s.rttMillis) as avgRttMillis,
                   coalesce(sum(s.directBytes), 0) as directBytes,
                   coalesce(sum(s.relayBytes), 0) as relayBytes
            from PeerMeshSession s
            where s.tenantId = :tenantId
            group by case
                       when s.relayBytes > s.directBytes then 'RELAY'
                       when s.directBytes > s.relayBytes then 'DIRECT'
                       else s.pathType
                     end,
                     s.status
            """)
    List<PathTypeAggregate> aggregatePathTypes(String tenantId);

    @Query("""
            select case
                     when s.relayBytes > s.directBytes then 'RELAY'
                     when s.directBytes > s.relayBytes then 'DIRECT'
                     else s.pathType
                   end as pathType,
                   s.status as status,
                   count(s) as sessions, count(s.rttMillis) as reportedSessions,
                   avg(s.rttMillis) as avgRttMillis,
                   coalesce(sum(s.directBytes), 0) as directBytes,
                   coalesce(sum(s.relayBytes), 0) as relayBytes
            from PeerMeshSession s
            where s.tenantId = :tenantId
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            group by case
                       when s.relayBytes > s.directBytes then 'RELAY'
                       when s.directBytes > s.relayBytes then 'DIRECT'
                       else s.pathType
                     end,
                     s.status
            """)
    List<PathTypeAggregate> aggregateVisiblePathTypes(String tenantId, List<Long> clientIds);

    @Query("""
            select case
                     when s.remoteEndpoint is null or trim(s.remoteEndpoint) = '' then 'UNKNOWN'
                     when s.remoteEndpoint like '[%' then 'IPv6'
                     else 'IPv4'
                   end as addressFamily,
                   s.status as status,
                   case
                     when s.relayBytes > s.directBytes then 'RELAY'
                     when s.directBytes > s.relayBytes then 'DIRECT'
                     else s.pathType
                   end as pathType,
                   count(s) as sessions,
                   count(s.rttMillis) as reportedSessions
            from PeerMeshSession s
            where s.tenantId = :tenantId
            group by case
                       when s.remoteEndpoint is null or trim(s.remoteEndpoint) = '' then 'UNKNOWN'
                       when s.remoteEndpoint like '[%' then 'IPv6'
                       else 'IPv4'
                     end,
                     s.status,
                     case
                       when s.relayBytes > s.directBytes then 'RELAY'
                       when s.directBytes > s.relayBytes then 'DIRECT'
                       else s.pathType
                     end
            """)
    List<AddressFamilyAggregate> aggregateAddressFamilies(String tenantId);

    @Query("""
            select case
                     when s.remoteEndpoint is null or trim(s.remoteEndpoint) = '' then 'UNKNOWN'
                     when s.remoteEndpoint like '[%' then 'IPv6'
                     else 'IPv4'
                   end as addressFamily,
                   s.status as status,
                   case
                     when s.relayBytes > s.directBytes then 'RELAY'
                     when s.directBytes > s.relayBytes then 'DIRECT'
                     else s.pathType
                   end as pathType,
                   count(s) as sessions,
                   count(s.rttMillis) as reportedSessions
            from PeerMeshSession s
            where s.tenantId = :tenantId
              and (s.sourceClientId in :clientIds or s.targetClientId in :clientIds)
            group by case
                       when s.remoteEndpoint is null or trim(s.remoteEndpoint) = '' then 'UNKNOWN'
                       when s.remoteEndpoint like '[%' then 'IPv6'
                       else 'IPv4'
                     end,
                     s.status,
                     case
                       when s.relayBytes > s.directBytes then 'RELAY'
                       when s.directBytes > s.relayBytes then 'DIRECT'
                       else s.pathType
                     end
            """)
    List<AddressFamilyAggregate> aggregateVisibleAddressFamilies(String tenantId, List<Long> clientIds);
}
