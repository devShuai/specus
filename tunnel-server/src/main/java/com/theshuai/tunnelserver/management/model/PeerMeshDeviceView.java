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
        String virtualDeviceMode,
        String virtualDeviceName,
        String virtualDeviceStatus,
        String virtualDeviceError,
        String virtualDeviceUpdatedAt,
        String lastSeenAt,
        String updatedAt
) {
}
