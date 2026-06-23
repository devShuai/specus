package com.theshuai.tunnelserver.management.model;

public record ClientAccountView(
        long id,
        String clientName,
        String ownerUsername,
        boolean enabled,
        int connectionRateLimitPerMinute,
        boolean online,
        Long connectedSinceMs,
        long uploadBytes,
        long downloadBytes,
        String createdAt,
        String updatedAt
) {
}
