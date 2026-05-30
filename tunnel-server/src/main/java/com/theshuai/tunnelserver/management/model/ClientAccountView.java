package com.theshuai.tunnelserver.management.model;

public record ClientAccountView(
        long id,
        String clientName,
        boolean enabled,
        int connectionRateLimitPerMinute,
        boolean online,
        long uploadBytes,
        long downloadBytes,
        String createdAt,
        String updatedAt
) {
}
