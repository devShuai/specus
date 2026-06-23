package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ClientCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ClientCredentialRepository extends JpaRepository<ClientCredential, Long> {
    Optional<ClientCredential> findByApiKey(String apiKey);

    Optional<ClientCredential> findByIdAndTenantId(Long id, String tenantId);

    Optional<ClientCredential> findByIdAndTenantIdAndOwnerUsername(Long id, String tenantId, String ownerUsername);

    List<ClientCredential> findByTenantIdOrderByIdDesc(String tenantId);

    List<ClientCredential> findByTenantIdAndOwnerUsernameOrderByIdDesc(String tenantId, String ownerUsername);

    long countByTenantId(String tenantId);
}
