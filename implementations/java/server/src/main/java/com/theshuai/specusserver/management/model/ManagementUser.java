package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "specus_management_user",
        indexes = {
                @Index(name = "idx_management_user_tenant", columnList = "tenant_id"),
                @Index(name = "idx_management_user_role", columnList = "role"),
                @Index(
                        name = "uq_management_user_oidc_identity_key",
                        columnList = "oidc_identity_key",
                        unique = true)
        })
@Getter
@Setter
public class ManagementUser {
    @Id
    @Column(length = 80)
    private String username;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "password_hash", nullable = false, length = 64)
    private String passwordHash;

    @Column(name = "oidc_issuer", length = 255)
    private String oidcIssuer;

    @Column(name = "oidc_subject", length = 255)
    private String oidcSubject;

    @Column(name = "oidc_identity_key", length = 64)
    private String oidcIdentityKey;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private ManagementRole role = ManagementRole.USER;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
