package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "tunnel_http_media_capture",
        indexes = {
                @Index(name = "idx_http_media_tenant_id", columnList = "tenant_id, id"),
                @Index(name = "idx_http_media_tenant_client_id", columnList = "tenant_id, client_id, id"),
                @Index(name = "idx_http_media_resource", columnList = "tenant_id, resource_key, id"),
                @Index(name = "idx_http_media_source", columnList = "tenant_id, client_id, route, id"),
                @Index(name = "idx_http_media_expiry", columnList = "state, expires_at")
        })
@Getter
@Setter
public class HttpMediaCapture {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(nullable = false, length = 128)
    private String route;

    @Column(name = "resource_id")
    private Long resourceId;

    @Column(name = "source_url", nullable = false, length = 3072)
    private String sourceUrl;

    @Column(name = "resource_key", nullable = false, length = 64)
    private String resourceKey;

    @Column(nullable = false, length = 16)
    private String method;

    @Column(name = "status_code", nullable = false)
    private int statusCode;

    @Column(name = "content_type", length = 255)
    private String contentType;

    @Column(name = "content_encoding", length = 128)
    private String contentEncoding;

    @Column(name = "media_kind", nullable = false, length = 32)
    private String mediaKind;

    @Column(name = "entity_tag", length = 512)
    private String entityTag;

    @Column(name = "last_modified", length = 128)
    private String lastModified;

    @Column(name = "content_range_start")
    private Long contentRangeStart;

    @Column(name = "content_range_end")
    private Long contentRangeEnd;

    @Column(name = "total_bytes")
    private Long totalBytes;

    @Column(name = "captured_bytes", nullable = false)
    private long capturedBytes;

    @Column(name = "segment_sequence")
    private Long segmentSequence;

    @Column(name = "initialization_segment", nullable = false)
    private boolean initializationSegment;

    @Column(name = "live_stream", nullable = false)
    private boolean liveStream;

    @Column(name = "object_key", nullable = false, length = 1024)
    private String objectKey;

    @Column(name = "upload_id", length = 1024)
    private String uploadId;

    @Column(name = "object_etag", length = 512)
    private String objectEtag;

    @Column(nullable = false, length = 24)
    private String state;

    @Column(name = "failure_reason", length = 2048)
    private String failureReason;

    @Lob
    @Column(name = "response_headers")
    private String responseHeaders;

    @Column(name = "captured_at", nullable = false, length = 40)
    private String capturedAt;

    @Column(name = "completed_at", length = 40)
    private String completedAt;

    @Column(name = "expires_at", nullable = false, length = 40)
    private String expiresAt;
}
