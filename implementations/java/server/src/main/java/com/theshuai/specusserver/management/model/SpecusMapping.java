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
@Table(name = "specus_mapping",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_specus_mapping_listen_port",
                columnNames = "listen_port"
        ),
        indexes = {
                @Index(name = "idx_specus_mapping_tenant", columnList = "tenant_id"),
                @Index(name = "idx_specus_mapping_client", columnList = "client_id"),
                @Index(name = "idx_specus_mapping_tenant_client_id", columnList = "tenant_id, client_id, id"),
                @Index(name = "idx_specus_mapping_tenant_client_enabled_id", columnList = "tenant_id, client_id, enabled, id")
        })
@Getter
@Setter
public class SpecusMapping {
    @Id
    private Long id;

    @Column(name = "tenant_id", length = 80)
    private String tenantId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "listen_port", nullable = false)
    private int listenPort;

    @Column(name = "target_address", nullable = false, length = 255)
    private String targetAddress;

    @Column(name = "target_port", nullable = false)
    private int targetPort;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "detail_capture_enabled")
    private Boolean detailCaptureEnabled = false;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
