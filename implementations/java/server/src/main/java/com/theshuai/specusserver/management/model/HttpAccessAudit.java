package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

/**
 * One entry of the HTTP access audit: who changed whose access to a route or share, and when. It
 * never holds a token, a token hash, a label, Basic credentials, a target address or anything about
 * visitors. Written in the same transaction as the change it describes.
 */
@Entity
@Table(name = "http_access_audit",
        indexes = {
                @Index(name = "idx_http_access_audit_at", columnList = "occurred_at"),
                @Index(name = "idx_http_access_audit_route", columnList = "tenant_id, route_id, id")
        })
@Getter
@Setter
public class HttpAccessAudit {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    /** Epoch seconds UTC ({@code at} in the API). */
    @Column(name = "occurred_at", nullable = false)
    private Long occurredAt;

    /** {@code null} for system actions (sweep, read-time revocation, expiry). */
    @Column(name = "actor", length = 120)
    private String actor;

    @Column(name = "action", nullable = false, length = 40)
    private String action;

    @Column(name = "route_id", nullable = false)
    private Long routeId;

    @Column(name = "share_id", length = 16)
    private String shareId;

    /** Compact JSON object; its keys depend on the action. */
    @Column(name = "detail_json", nullable = false, length = 512)
    private String detailJson;
}
