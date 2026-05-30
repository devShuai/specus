package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "tunnel_client_account")
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

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getConnectionRateLimitPerMinute() {
        return connectionRateLimitPerMinute;
    }

    public void setConnectionRateLimitPerMinute(int connectionRateLimitPerMinute) {
        this.connectionRateLimitPerMinute = connectionRateLimitPerMinute;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }
}
