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
@Table(name = "tunnel_mapping",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_tunnel_mapping_listen_port",
                columnNames = "listen_port"
        ),
        indexes = @Index(name = "idx_tunnel_mapping_client", columnList = "client_id"))
@Getter
@Setter
public class TunnelMapping {
    @Id
    private Long id;

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

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
