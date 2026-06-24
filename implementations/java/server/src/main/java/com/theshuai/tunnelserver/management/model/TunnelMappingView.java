package com.theshuai.tunnelserver.management.model;

public record TunnelMappingView(
        long id,
        long clientId,
        String clientName,
        int listenPort,
        String targetAddress,
        int targetPort,
        boolean enabled,
        boolean detailCaptureEnabled,
        String createdAt,
        String updatedAt
) {
}
