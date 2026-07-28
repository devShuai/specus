package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ManagementUserEmail;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ManagementUserEmailRepository extends JpaRepository<ManagementUserEmail, String> {
    boolean existsByEmailIgnoreCase(String email);
}
