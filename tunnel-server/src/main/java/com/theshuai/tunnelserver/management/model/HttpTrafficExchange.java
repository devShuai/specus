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
@Table(name = "tunnel_http_traffic_exchange",
        indexes = {
                @Index(name = "idx_http_exchange_tenant", columnList = "tenant_id"),
                @Index(name = "idx_http_exchange_client", columnList = "client_id"),
                @Index(name = "idx_http_exchange_route", columnList = "route"),
                @Index(name = "idx_http_exchange_captured_at", columnList = "captured_at")
        })
@Getter
@Setter
public class HttpTrafficExchange {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "route", nullable = false, length = 128)
    private String route;

    @Column(name = "resource_id")
    private Long resourceId;

    @Column(name = "resource_name", nullable = false, length = 255)
    private String resourceName;

    @Column(name = "method", nullable = false, length = 16)
    private String method;

    @Column(name = "relative_path", nullable = false, length = 1024)
    private String relativePath;

    @Column(name = "raw_query", length = 2048)
    private String rawQuery;

    @Column(name = "status_code", nullable = false)
    private int statusCode;

    @Column(name = "success", nullable = false)
    private boolean success;

    @Column(name = "error", length = 2048)
    private String error;

    @Column(name = "remote_address", length = 255)
    private String remoteAddress;

    @Column(name = "request_bytes", nullable = false)
    private long requestBytes;

    @Column(name = "response_bytes", nullable = false)
    private long responseBytes;

    @Column(name = "elapsed_ms", nullable = false)
    private long elapsedMs;

    @Column(name = "request_content_type", length = 255)
    private String requestContentType;

    @Column(name = "response_content_type", length = 255)
    private String responseContentType;

    @Column(name = "request_headers", length = 8192)
    private String requestHeaders;

    @Column(name = "response_headers", length = 8192)
    private String responseHeaders;

    @Column(name = "request_preview_hex", length = 4096)
    private String requestPreviewHex;

    @Lob
    @Column(name = "request_preview_text")
    private String requestPreviewText;

    @Column(name = "response_preview_hex", length = 4096)
    private String responsePreviewHex;

    @Column(name = "response_preview_text", length = 4096)
    private String responsePreviewText;

    @Column(name = "request_truncated", nullable = false)
    private boolean requestTruncated;

    @Column(name = "response_truncated", nullable = false)
    private boolean responseTruncated;

    @Column(name = "captured_at", nullable = false, length = 40)
    private String capturedAt;
}
