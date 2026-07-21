package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ManagementRegistrationChallenge;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ManagementRegistrationChallengeRepository
        extends JpaRepository<ManagementRegistrationChallenge, String> {
    Optional<ManagementRegistrationChallenge> findFirstByUsernameIgnoreCaseOrEmailIgnoreCase(
            String username, String email);

    long deleteByExpiresAtBefore(String expiresAt);
}
