package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "peer_mesh_session",
        indexes = {
                @Index(name = "idx_peer_mesh_session_tenant", columnList = "tenant_id"),
                @Index(name = "idx_peer_mesh_session_source", columnList = "tenant_id, source_client_id"),
                @Index(name = "idx_peer_mesh_session_target", columnList = "tenant_id, target_client_id"),
                @Index(name = "idx_peer_mesh_session_status", columnList = "status")
        })
@Getter
@Setter
public class PeerMeshSession {
    @Id
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "source_client_id", nullable = false)
    private Long sourceClientId;

    @Column(name = "source_client_name", nullable = false, length = 120)
    private String sourceClientName;

    @Column(name = "target_client_id", nullable = false)
    private Long targetClientId;

    @Column(name = "target_client_name", nullable = false, length = 120)
    private String targetClientName;

    @Column(name = "path_type", nullable = false, length = 40)
    private String pathType;

    @Column(nullable = false, length = 40)
    private String status;

    @Column(name = "token_hash", length = 64)
    private String tokenHash;

    @Column(name = "started_at", nullable = false, length = 40)
    private String startedAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;

    @Column(name = "expires_at", nullable = false, length = 40)
    private String expiresAt;

    @Column(name = "closed_at", length = 40)
    private String closedAt;
}
