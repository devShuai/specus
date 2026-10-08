package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ManagementRegistrationChallenge;
import com.theshuai.specusserver.management.model.SortableInstant;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ManagementRegistrationChallengeRepository
        extends JpaRepository<ManagementRegistrationChallenge, String> {
    Optional<ManagementRegistrationChallenge> findFirstByUsernameIgnoreCaseOrEmailIgnoreCase(
            String username, String email);

    /** {@code expiresAt} and the column are {@link SortableInstant} text, so the string order is the time order. */
    long deleteByExpiresAtBefore(String expiresAt);
}
