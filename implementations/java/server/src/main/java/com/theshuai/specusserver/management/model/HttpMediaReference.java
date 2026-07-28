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

@Entity
@Table(name = "specus_http_media_reference",
        indexes = {
                @Index(name = "idx_http_media_ref_manifest", columnList = "tenant_id, manifest_capture_id, sequence_index"),
                @Index(name = "idx_http_media_ref_source", columnList = "tenant_id, manifest_capture_id")
        })
@Getter
@Setter
public class HttpMediaReference {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "manifest_capture_id", nullable = false)
    private Long manifestCaptureId;

    @Column(name = "relation_type", nullable = false, length = 24)
    private String relationType;

    @Column(name = "sequence_index")
    private Long sequenceIndex;

    @Column(name = "original_uri", nullable = false, length = 2048)
    private String originalUri;

    @Column(name = "resolved_source_url", nullable = false, length = 3072)
    private String resolvedSourceUrl;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;
}
