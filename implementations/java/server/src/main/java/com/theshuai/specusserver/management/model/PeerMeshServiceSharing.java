package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "peer_mesh_service_sharing")
@Getter
@Setter
public class PeerMeshServiceSharing {
    @Id
    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(nullable = false)
    private boolean enabled = false;

    @Column(name = "mdns_import_enabled", nullable = false)
    private boolean mdnsImportEnabled = false;

    @Column(name = "updated_by", length = 80)
    private String updatedBy;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
