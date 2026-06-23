package com.theshuai.tunnelserver.management.model;

public record PeerMeshSessionView(
        long id,
        long sourceClientId,
        String sourceClientName,
        long targetClientId,
        String targetClientName,
        String pathType,
        String status,
        String startedAt,
        String updatedAt,
        String expiresAt,
        String closedAt
) {
}
