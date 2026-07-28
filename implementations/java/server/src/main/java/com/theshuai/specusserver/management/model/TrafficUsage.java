package com.theshuai.specusserver.management.model;

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

@Entity
@Table(name = "specus_traffic_usage",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_specus_traffic_client_date",
                columnNames = {"client_id", "usage_date"}
        ),
        indexes = {
                @Index(name = "idx_specus_traffic_tenant", columnList = "tenant_id"),
                @Index(name = "idx_specus_traffic_client", columnList = "client_id"),
                @Index(name = "idx_specus_traffic_tenant_date_id", columnList = "tenant_id, usage_date, id"),
                @Index(name = "idx_specus_traffic_tenant_client_date_id", columnList = "tenant_id, client_id, usage_date, id")
        })
@Getter
@Setter
public class TrafficUsage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", length = 80)
    private String tenantId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "usage_date", nullable = false, length = 10)
    private String usageDate;

    @Column(name = "upload_bytes", nullable = false)
    private long uploadBytes;

    @Column(name = "download_bytes", nullable = false)
    private long downloadBytes;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
