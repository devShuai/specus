package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "peer_mesh_shared_service",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_peer_shared_service_id",
                        columnNames = {"tenant_id", "client_id", "service_id"})
        },
        indexes = {
                @Index(name = "idx_peer_shared_service_tenant_client", columnList = "tenant_id, client_id"),
                @Index(name = "idx_peer_shared_service_tenant_enabled", columnList = "tenant_id, enabled")
        })
@Getter
@Setter
public class PeerMeshSharedService {
    @Id
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "service_id", nullable = false, length = 64)
    private String serviceId;

    @Column(nullable = false, length = 80)
    private String name;

    @Column(length = 200)
    private String description = "";

    @Column(nullable = false, length = 16)
    private String transport = "tcp";

    @Column(nullable = false, length = 16)
    private String application;

    @Column(name = "target_host", nullable = false, length = 64)
    private String targetHost;

    @Column(name = "target_port", nullable = false)
    private int targetPort;

    @Column(name = "published_port", nullable = false)
    private int publishedPort;

    @Column(length = 128)
    private String path = "";

    @Column(nullable = false)
    private boolean enabled = false;

    @Column(nullable = false, length = 16)
    private String visibility = "OWNER";

    @Column(name = "allowed_client_ids", length = 512)
    private String allowedClientIds = "";

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
