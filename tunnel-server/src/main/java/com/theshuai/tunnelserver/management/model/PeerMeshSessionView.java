package com.theshuai.tunnelserver.management.model;

public record PeerMeshSessionView(
        long id,
        long sourceClientId,
        String sourceClientName,
        long targetClientId,
        String targetClientName,
        String pathType,
        String status,
        Long rttMillis,
        String localEndpoint,
        String remoteEndpoint,
        String startedAt,
        String updatedAt,
        String expiresAt,
        String closedAt
) {
}
