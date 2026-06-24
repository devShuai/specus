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
@Table(name = "tunnel_client_identity",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_client_identity_machine_user",
                columnNames = {"credential_id", "machine_fingerprint", "os_user"}
        ),
        indexes = {
                @Index(name = "idx_client_identity_tenant", columnList = "tenant_id"),
                @Index(name = "idx_client_identity_client", columnList = "client_id")
        })
@Getter
@Setter
public class ClientIdentity {
    @Id
    private Long id;

    @Column(name = "tenant_id", length = 80, nullable = false)
    private String tenantId;

    @Column(name = "credential_id", nullable = false)
    private Long credentialId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "machine_fingerprint", nullable = false, length = 160)
    private String machineFingerprint;

    @Column(name = "os_user", nullable = false, length = 120)
    private String osUser;

    @Column(name = "hostname", length = 160)
    private String hostname;

    @Column(name = "first_seen_at", nullable = false, length = 40)
    private String firstSeenAt;

    @Column(name = "last_seen_at", nullable = false, length = 40)
    private String lastSeenAt;
}
