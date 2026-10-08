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
import org.hibernate.Length;

@Entity
@Table(name = "specus_http_traffic_exchange",
        indexes = {
                @Index(name = "idx_http_exchange_tenant", columnList = "tenant_id"),
                @Index(name = "idx_http_exchange_client", columnList = "client_id"),
                @Index(name = "idx_http_exchange_route", columnList = "route"),
                @Index(name = "idx_http_exchange_response_body_type", columnList = "response_body_type"),
                @Index(name = "idx_http_exchange_captured_at", columnList = "captured_at"),
                @Index(name = "idx_http_exchange_tenant_id", columnList = "tenant_id, id"),
                @Index(name = "idx_http_exchange_tenant_client_id", columnList = "tenant_id, client_id, id"),
                @Index(name = "idx_http_exchange_tenant_route_id", columnList = "tenant_id, route, id"),
                @Index(name = "idx_http_exchange_tenant_client_route_id", columnList = "tenant_id, client_id, route, id"),
                @Index(name = "idx_http_exchange_tenant_body_type_id", columnList = "tenant_id, response_body_type, id")
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

    @Column(name = "response_body_type", length = 32)
    private String responseBodyType;

    // Text, not varchar(8192): MySQL counts a varchar at 4 bytes a character against its 65,535-byte
    // row limit, and these two alone reach it. specus.traffic.capture-header-chars caps the content.
    @Column(name = "request_headers", length = Length.LONG32)
    private String requestHeaders;

    @Column(name = "response_headers", length = Length.LONG32)
    private String responseHeaders;

    @Column(name = "request_preview_hex", length = 4096)
    private String requestPreviewHex;

    // Not @Lob: on PostgreSQL a @Lob is an oid column bound through the large-object API, which
    // refuses to run outside a transaction, and a LIKE on it binds the keyword as a new large object.
    // Length.LONG32 makes these bytea and text there, longblob and longtext on MySQL, and SQLite keeps
    // binding them as bytes and a string. HttpExchangeLargeObjectMigrator converts the oid columns.
    @Column(name = "request_body_data", length = Length.LONG32)
    private byte[] requestBodyData;

    @Column(name = "request_preview_text", length = Length.LONG32)
    private String requestPreviewText;

    @Column(name = "response_preview_hex", length = 4096)
    private String responsePreviewHex;

    @Column(name = "response_body_data", length = Length.LONG32)
    private byte[] responseBodyData;

    @Column(name = "response_preview_text", length = Length.LONG32)
    private String responsePreviewText;

    @Column(name = "request_truncated", nullable = false)
    private boolean requestTruncated;

    @Column(name = "response_truncated", nullable = false)
    private boolean responseTruncated;

    @Column(name = "captured_at", nullable = false, length = 40)
    private String capturedAt;
}
