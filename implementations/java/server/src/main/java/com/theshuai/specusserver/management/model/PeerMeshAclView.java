package com.theshuai.specusserver.management.model;

public record PeerMeshAclView(
        long id,
        long sourceClientId,
        String sourceClientName,
        long targetClientId,
        String targetClientName,
        boolean allowed,
        String direction,
        String createdAt,
        String updatedAt
) {
}
