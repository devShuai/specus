package com.theshuai.specusserver.management.model;

public record ClientAccountView(
        long id,
        String clientName,
        String ownerUsername,
        boolean enabled,
        int connectionRateLimitPerMinute,
        boolean online,
        Long connectedSinceMs,
        String clientVersion,
        boolean messageSendCapable,
        boolean messageReceiveCapable,
        boolean messageAttachmentsCapable,
        boolean messageMediaPreviewCapable,
        long messageMaxAttachmentBytes,
        long uploadBytes,
        long downloadBytes,
        String createdAt,
        String updatedAt
) {
}
