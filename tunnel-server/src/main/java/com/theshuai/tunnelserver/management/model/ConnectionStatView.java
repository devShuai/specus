package com.theshuai.tunnelserver.management.model;

public record ConnectionStatView(
        long id,
        Long clientId,
        String clientName,
        String month,
        long total,
        long success,
        long failure,
        String updatedAt
) {
}
