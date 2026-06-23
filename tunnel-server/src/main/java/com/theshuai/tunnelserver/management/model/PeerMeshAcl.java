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
@Table(name = "peer_mesh_acl",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_peer_mesh_acl_pair",
                columnNames = {"tenant_id", "source_client_id", "target_client_id"}
        ),
        indexes = {
                @Index(name = "idx_peer_mesh_acl_source", columnList = "tenant_id, source_client_id"),
                @Index(name = "idx_peer_mesh_acl_target", columnList = "tenant_id, target_client_id")
        })
@Getter
@Setter
public class PeerMeshAcl {
    @Id
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "owner_username", nullable = false, length = 80)
    private String ownerUsername;

    @Column(name = "source_client_id", nullable = false)
    private Long sourceClientId;

    @Column(name = "source_client_name", nullable = false, length = 120)
    private String sourceClientName;

    @Column(name = "target_client_id", nullable = false)
    private Long targetClientId;

    @Column(name = "target_client_name", nullable = false, length = 120)
    private String targetClientName;

    @Column(nullable = false)
    private boolean allowed = true;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
