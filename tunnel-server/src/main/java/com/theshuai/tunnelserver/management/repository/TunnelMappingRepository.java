package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.TunnelMapping;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TunnelMappingRepository extends JpaRepository<TunnelMapping, Long> {
    List<TunnelMapping> findAllByOrderByIdDesc();

    List<TunnelMapping> findByClientIdOrderByIdDesc(Long clientId);

    List<TunnelMapping> findByClientIdAndEnabledTrueOrderByIdAsc(Long clientId);

    Optional<TunnelMapping> findByListenPort(int listenPort);
}
