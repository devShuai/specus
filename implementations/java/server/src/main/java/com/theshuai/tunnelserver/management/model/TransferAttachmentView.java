package com.theshuai.tunnelserver.management.model;

public record TransferAttachmentView(
        long attachmentId,
        String objectId,
        String fileName,
        String mimeType,
        long sizeBytes,
        String sha256,
        String status,
        String expiresAt
) {
}
