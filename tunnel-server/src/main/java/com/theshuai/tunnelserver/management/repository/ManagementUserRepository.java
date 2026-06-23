package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ManagementUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ManagementUserRepository extends JpaRepository<ManagementUser, String> {
    Optional<ManagementUser> findByUsernameIgnoreCase(String username);

    boolean existsByUsernameIgnoreCase(String username);

    List<ManagementUser> findByTenantIdOrderByUsernameAsc(String tenantId);
}
