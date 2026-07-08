package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "transfer_attachment",
        indexes = {
                @Index(name = "idx_transfer_attachment_tenant", columnList = "tenant_id, scope, id"),
                @Index(name = "idx_transfer_attachment_room", columnList = "scope, room_id, id"),
                @Index(name = "idx_transfer_attachment_expires", columnList = "expires_at, status")
        })
@Getter
@Setter
public class TransferAttachment {
    @Id
    private Long id;

    @Column(name = "tenant_id", length = 80)
    private String tenantId;

    @Column(name = "scope", nullable = false, length = 40)
    private String scope;

    @Column(name = "room_id", length = 120)
    private String roomId;

    @Column(name = "room_token_hash", length = 64)
    private String roomTokenHash;

    @Column(name = "owner_username", length = 80)
    private String ownerUsername;

    @Column(name = "target_client_id")
    private Long targetClientId;

    @Column(name = "object_key", nullable = false, length = 512)
    private String objectKey;

    @Column(name = "file_name", nullable = false, length = 255)
    private String fileName;

    @Column(name = "mime_type", nullable = false, length = 120)
    private String mimeType;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Column(name = "sha256", length = 64)
    private String sha256;

    @Column(name = "status", nullable = false, length = 24)
    private String status;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;

    @Column(name = "upload_expires_at", nullable = false, length = 40)
    private String uploadExpiresAt;

    @Column(name = "expires_at", nullable = false, length = 40)
    private String expiresAt;

    @Column(name = "uploaded_at", length = 40)
    private String uploadedAt;
}
