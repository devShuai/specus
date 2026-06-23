package com.theshuai.tunnelserver.management.model;

public record PeerMeshDeviceView(
        long id,
        long clientId,
        String clientName,
        String ownerUsername,
        boolean enabled,
        boolean online,
        String virtualIp,
        String cidr,
        String publicKey,
        String natType,
        String lastEndpoint,
        String lastSeenAt,
        String updatedAt
) {
}
