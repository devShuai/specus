package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A temporary HTTP share: a revocable, expiring grant for one protected HTTP route, reached under
 * {@code /http-share/{shareId}/} (protocol/spec/temporary-http-share.md). Only the SHA-256 of the
 * token is stored. Every time column is integer epoch seconds UTC, the same in all servers sharing
 * this table.
 */
@Entity
@Table(name = "http_share",
        indexes = {
                @Index(name = "idx_http_share_route", columnList = "route_id"),
                @Index(name = "idx_http_share_creator", columnList = "tenant_id, created_by"),
                @Index(name = "idx_http_share_expires", columnList = "expires_at")
        })
@Getter
@Setter
public class HttpShare {
    @Id
    @Column(name = "share_id", length = 16)
    private String shareId;

    /** The route's tenant when the share was created. */
    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "route_id", nullable = false)
    private Long routeId;

    @Column(name = "token_sha256", nullable = false, length = 64)
    private String tokenSha256;

    /** {@code read} or {@code full}. */
    @Column(name = "access", nullable = false, length = 8)
    private String access;

    @Column(name = "path_prefix", nullable = false, length = 256)
    private String pathPrefix;

    @Column(name = "label", length = 255)
    private String label;

    @Column(name = "created_by", nullable = false, length = 120)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Long createdAt;

    @Column(name = "expires_at", nullable = false)
    private Long expiresAt;

    @Column(name = "revoked_at")
    private Long revokedAt;

    /** {@code null} for a revocation by the system. */
    @Column(name = "revoked_by", length = 120)
    private String revokedBy;

    @Column(name = "revoke_reason", length = 40)
    private String revokeReason;

    /**
     * Set once the sweep has written {@code share.expired}. An integer 0/1 rather than a boolean so
     * that every server maps the shared column the same way (TINYINT/SMALLINT/INTEGER by dialect).
     */
    @JdbcTypeCode(SqlTypes.TINYINT)
    @ColumnDefault("0")
    @Column(name = "expiry_recorded", nullable = false)
    private int expiryRecorded;
}
