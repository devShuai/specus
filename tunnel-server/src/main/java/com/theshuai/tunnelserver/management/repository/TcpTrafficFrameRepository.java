package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.TcpTrafficFrame;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TcpTrafficFrameRepository extends JpaRepository<TcpTrafficFrame, Long> {
    List<TcpTrafficFrame> findByTenantIdOrderByIdDesc(String tenantId, Pageable pageable);

    List<TcpTrafficFrame> findByTenantIdAndClientIdOrderByIdDesc(
            String tenantId, Long clientId, Pageable pageable);

    List<TcpTrafficFrame> findByTenantIdAndListenPortOrderByIdDesc(
            String tenantId, int listenPort, Pageable pageable);

    List<TcpTrafficFrame> findByTenantIdAndClientIdAndListenPortOrderByIdDesc(
            String tenantId, Long clientId, int listenPort, Pageable pageable);
}
