package com.theshuai.tunnelserver.management.model;

public record TrafficUsageView(
        long id,
        long clientId,
        String clientName,
        String usageDate,
        long uploadBytes,
        long downloadBytes,
        String updatedAt
) {
}
