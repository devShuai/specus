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
@Table(name = "peer_mesh_device",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_peer_mesh_device_client", columnNames = {"tenant_id", "client_id"}),
                @UniqueConstraint(name = "uk_peer_mesh_device_ip", columnNames = {"tenant_id", "virtual_ip"})
        },
        indexes = {
                @Index(name = "idx_peer_mesh_device_owner", columnList = "tenant_id, owner_username"),
                @Index(name = "idx_peer_mesh_device_client_name", columnList = "client_name")
        })
@Getter
@Setter
public class PeerMeshDevice {
    @Id
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "owner_username", nullable = false, length = 80)
    private String ownerUsername;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "virtual_ip", nullable = false, length = 64)
    private String virtualIp;

    @Column(name = "cidr", nullable = false, length = 64)
    private String cidr;

    @Column(name = "public_key", length = 256)
    private String publicKey;

    @Column(name = "nat_type", length = 80)
    private String natType;

    @Column(name = "last_endpoint", length = 255)
    private String lastEndpoint;

    @Column(name = "virtual_device_mode", length = 80)
    private String virtualDeviceMode;

    @Column(name = "virtual_device_name", length = 80)
    private String virtualDeviceName;

    @Column(name = "virtual_device_status", length = 80)
    private String virtualDeviceStatus;

    @Column(name = "virtual_device_error", length = 512)
    private String virtualDeviceError;

    @Column(name = "virtual_device_updated_at", length = 40)
    private String virtualDeviceUpdatedAt;

    @Column(nullable = false)
    private boolean enabled = false;

    @Column(name = "last_seen_at", length = 40)
    private String lastSeenAt;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
