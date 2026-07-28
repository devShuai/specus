package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "specus_management_registration_challenge",
        indexes = {
                @Index(name = "uq_registration_challenge_username", columnList = "username", unique = true),
                @Index(name = "uq_registration_challenge_email", columnList = "email", unique = true),
                @Index(name = "idx_registration_challenge_expiry", columnList = "expires_at")
        })
@Getter
@Setter
public class ManagementRegistrationChallenge {
    @Id
    @Column(name = "registration_id", length = 64)
    private String registrationId;

    @Column(nullable = false, length = 80)
    private String username;

    @Column(nullable = false, length = 254)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 64)
    private String passwordHash;

    @Column(name = "code_hash", nullable = false, length = 64)
    private String codeHash;

    @Column(name = "attempts_remaining", nullable = false)
    private int attemptsRemaining;

    @Column(name = "expires_at", nullable = false, length = 40)
    private String expiresAt;

    @Column(name = "resend_available_at", nullable = false, length = 40)
    private String resendAvailableAt;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
