package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ManagementUserEmail;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ManagementUserEmailRepository extends JpaRepository<ManagementUserEmail, String> {
    boolean existsByEmailIgnoreCase(String email);
}
