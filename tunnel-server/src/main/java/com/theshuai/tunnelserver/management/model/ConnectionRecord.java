package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "tunnel_connection_record", indexes = {
        // Composite serves the per-login rate-limit COUNT (client_id = ? AND connected_at >= ?)
        // and per-client history listings ordered by time.
        @Index(name = "idx_tunnel_connection_client_time", columnList = "client_id, connected_at"),
        // Serves the retention purge (connected_at < cutoff).
        @Index(name = "idx_tunnel_connection_connected_at", columnList = "connected_at")
})
@Getter
@Setter
public class ConnectionRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id")
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "channel_id", length = 160)
    private String channelId;

    @Column(name = "remote_address", length = 255)
    private String remoteAddress;

    @Column(name = "connected_at", nullable = false, length = 40)
    private String connectedAt;

    @Column(name = "disconnected_at", length = 40)
    private String disconnectedAt;

    @Column(nullable = false)
    private boolean success;

    @Column(name = "failure_reason", length = 255)
    private String failureReason;

    /**
     * 断开原因机器码（{@link DisconnectReason#name()}）。登录失败时也会写一份 {@link DisconnectReason#LOGIN_FAILURE}，
     * 但失败细节仍保留在 {@link #failureReason}。
     */
    @Column(name = "disconnect_reason", length = 40)
    private String disconnectReason;
}
