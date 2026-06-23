package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "tunnel_client_credential",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_client_credential_api_key",
                columnNames = "api_key"
        ),
        indexes = {
                @Index(name = "idx_client_credential_tenant", columnList = "tenant_id"),
                @Index(name = "idx_client_credential_owner", columnList = "tenant_id, owner_username")
        })
@Getter
@Setter
public class ClientCredential {
    @Id
    private Long id;

    @Column(name = "tenant_id", length = 80, nullable = false)
    private String tenantId;

    @Column(name = "owner_username", length = 80)
    private String ownerUsername;

    @Column(name = "api_key", length = 120, nullable = false)
    private String apiKey;

    @Column(name = "secret_hash", length = 64, nullable = false)
    private String secretHash;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "max_online_instances", nullable = false)
    private int maxOnlineInstances = 2;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
