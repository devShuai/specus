package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "transfer_attachment_download_grant",
        indexes = {
                @Index(name = "uk_attachment_download_grant_token", columnList = "token_hash", unique = true),
                @Index(name = "idx_attachment_download_grant_attachment", columnList = "attachment_id, created_at"),
                @Index(name = "idx_attachment_download_grant_expires", columnList = "expires_at, consumed_at")
        })
@Getter
@Setter
public class TransferAttachmentDownloadGrant {
    @Id
    private Long id;

    @Column(name = "token_hash", nullable = false, length = 64, unique = true)
    private String tokenHash;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "username", nullable = false, length = 80)
    private String username;

    @Column(name = "attachment_id", nullable = false)
    private Long attachmentId;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "expires_at", nullable = false, length = 40)
    private String expiresAt;

    @Column(name = "consumed_at", length = 40)
    private String consumedAt;
}
