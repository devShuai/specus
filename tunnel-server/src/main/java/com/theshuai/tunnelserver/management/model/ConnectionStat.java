package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

/**
 * Per-natural-month connection totals kept after the raw {@code tunnel_connection_record} detail is
 * archived. One row per (clientName, statMonth) where statMonth is {@code yyyy-MM}.
 */
@Entity
@Table(name = "tunnel_connection_stat",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_tunnel_connection_stat",
                columnNames = {"client_name", "stat_month"}
        ),
        indexes = @Index(name = "idx_tunnel_connection_stat_client", columnList = "client_name"))
@Getter
@Setter
public class ConnectionStat {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id")
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "stat_month", nullable = false, length = 7)
    private String statMonth;

    @Column(name = "total_count", nullable = false)
    private long totalCount;

    @Column(name = "success_count", nullable = false)
    private long successCount;

    @Column(name = "failure_count", nullable = false)
    private long failureCount;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
