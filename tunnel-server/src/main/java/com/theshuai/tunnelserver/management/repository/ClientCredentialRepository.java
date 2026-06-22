package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ClientCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ClientCredentialRepository extends JpaRepository<ClientCredential, Long> {
    Optional<ClientCredential> findByApiKey(String apiKey);

    Optional<ClientCredential> findByIdAndTenantId(Long id, String tenantId);

    List<ClientCredential> findByTenantIdOrderByIdDesc(String tenantId);

    long countByTenantId(String tenantId);
}
