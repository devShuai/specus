package com.theshuai.tunnelserver.management.model;

public record PeerMeshAclView(
        long id,
        long sourceClientId,
        String sourceClientName,
        long targetClientId,
        String targetClientName,
        boolean allowed,
        String createdAt,
        String updatedAt
) {
}
