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

@Entity
@Table(name = "tunnel_resource_traffic_usage",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_resource_traffic_resource_date",
                columnNames = {"tenant_id", "client_id", "resource_type", "resource_key", "usage_date"}
        ),
        indexes = {
                @Index(name = "idx_resource_traffic_tenant", columnList = "tenant_id"),
                @Index(name = "idx_resource_traffic_client", columnList = "client_id"),
                @Index(name = "idx_resource_traffic_type", columnList = "resource_type"),
                @Index(name = "idx_resource_traffic_date", columnList = "usage_date"),
                @Index(name = "idx_resource_traffic_tenant_date_id", columnList = "tenant_id, usage_date, id"),
                @Index(name = "idx_resource_traffic_tenant_client_date_id", columnList = "tenant_id, client_id, usage_date, id"),
                @Index(name = "idx_resource_traffic_tenant_type_date_id", columnList = "tenant_id, resource_type, usage_date, id"),
                @Index(name = "idx_resource_traffic_tenant_client_type_date_id", columnList = "tenant_id, client_id, resource_type, usage_date, id")
        })
@Getter
@Setter
public class ResourceTrafficUsage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "resource_type", nullable = false, length = 32)
    private String resourceType;

    @Column(name = "resource_key", nullable = false, length = 128)
    private String resourceKey;

    @Column(name = "resource_id")
    private Long resourceId;

    @Column(name = "resource_name", nullable = false, length = 255)
    private String resourceName;

    @Column(name = "usage_date", nullable = false, length = 10)
    private String usageDate;

    @Column(name = "upload_bytes", nullable = false)
    private long uploadBytes;

    @Column(name = "download_bytes", nullable = false)
    private long downloadBytes;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
