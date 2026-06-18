package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "tunnel_client_account")
@Getter
@Setter
public class ClientAccount {
    @Id
    private Long id;

    @Column(name = "client_name", nullable = false, unique = true, length = 120)
    private String clientName;

    @Column(name = "password_hash", nullable = false, length = 64)
    private String passwordHash;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "connection_rate_limit_per_minute", nullable = false)
    private int connectionRateLimitPerMinute = 30;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
