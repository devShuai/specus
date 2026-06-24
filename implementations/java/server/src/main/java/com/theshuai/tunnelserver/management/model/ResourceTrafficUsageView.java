package com.theshuai.tunnelserver.management.model;

public record ResourceTrafficUsageView(
        long id,
        long clientId,
        String clientName,
        String resourceType,
        String resourceKey,
        Long resourceId,
        String resourceName,
        String usageDate,
        long uploadBytes,
        long downloadBytes,
        String updatedAt
) {
}
