package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.TcpTrafficFrame;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TcpTrafficFrameRepository extends JpaRepository<TcpTrafficFrame, Long> {
    Optional<TcpTrafficFrame> findByTenantIdAndId(String tenantId, Long id);

    Optional<TcpTrafficFrame> findByTenantIdAndIdAndClientIdIn(String tenantId, Long id, List<Long> clientIds);

    Page<TcpTrafficFrame> findByTenantIdOrderByIdDesc(String tenantId, Pageable pageable);

    Page<TcpTrafficFrame> findByTenantIdAndClientIdOrderByIdDesc(
            String tenantId, Long clientId, Pageable pageable);

    Page<TcpTrafficFrame> findByTenantIdAndClientIdInOrderByIdDesc(
            String tenantId, List<Long> clientIds, Pageable pageable);

    Page<TcpTrafficFrame> findByTenantIdAndListenPortOrderByIdDesc(
            String tenantId, int listenPort, Pageable pageable);

    Page<TcpTrafficFrame> findByTenantIdAndClientIdAndListenPortOrderByIdDesc(
            String tenantId, Long clientId, int listenPort, Pageable pageable);

    Page<TcpTrafficFrame> findByTenantIdAndClientIdInAndListenPortOrderByIdDesc(
            String tenantId, List<Long> clientIds, int listenPort, Pageable pageable);

    Page<TcpTrafficFrame> findByTenantIdAndChannelIdOrderByIdAsc(
            String tenantId, String channelId, Pageable pageable);

    Page<TcpTrafficFrame> findByTenantIdAndChannelIdAndClientIdInOrderByIdAsc(
            String tenantId, String channelId, List<Long> clientIds, Pageable pageable);
}
