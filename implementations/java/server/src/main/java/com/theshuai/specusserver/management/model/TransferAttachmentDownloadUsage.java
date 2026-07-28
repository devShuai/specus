package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "transfer_attachment_download_usage",
        indexes = {
                @Index(name = "idx_attachment_download_usage_account_month",
                        columnList = "tenant_id, username, usage_month"),
                @Index(name = "idx_attachment_download_usage_attachment",
                        columnList = "attachment_id, created_at")
        })
@Getter
@Setter
public class TransferAttachmentDownloadUsage {
    @Id
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "username", nullable = false, length = 80)
    private String username;

    @Column(name = "attachment_id", nullable = false)
    private Long attachmentId;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Column(name = "usage_month", nullable = false, length = 7)
    private String usageMonth;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;
}
