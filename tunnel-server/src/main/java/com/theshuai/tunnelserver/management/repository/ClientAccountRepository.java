package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ClientAccountRepository extends JpaRepository<ClientAccount, Long> {
    Optional<ClientAccount> findByClientName(String clientName);

    Optional<ClientAccount> findByTenantIdAndClientName(String tenantId, String clientName);

    Optional<ClientAccount> findByIdAndTenantId(Long id, String tenantId);

    Optional<ClientAccount> findByIdAndTenantIdAndOwnerUsername(Long id, String tenantId, String ownerUsername);

    List<ClientAccount> findByTenantIdOrderByIdDesc(String tenantId);

    List<ClientAccount> findByTenantIdAndOwnerUsernameOrderByIdDesc(String tenantId, String ownerUsername);

    long countByTenantId(String tenantId);
}
