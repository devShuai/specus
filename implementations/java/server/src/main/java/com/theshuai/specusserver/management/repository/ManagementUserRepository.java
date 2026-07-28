package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ManagementUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ManagementUserRepository extends JpaRepository<ManagementUser, String> {
    Optional<ManagementUser> findByUsernameIgnoreCase(String username);

    boolean existsByUsernameIgnoreCase(String username);

    List<ManagementUser> findByTenantIdOrderByUsernameAsc(String tenantId);
}
