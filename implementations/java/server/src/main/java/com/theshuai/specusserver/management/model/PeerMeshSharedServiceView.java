package com.theshuai.specusserver.management.model;

import com.theshuai.common.peermesh.PeerAdvertisedService;

import java.util.List;

public record PeerMeshSharedServiceView(
        long id,
        String serviceId,
        long clientId,
        String clientName,
        String name,
        String description,
        String transport,
        String application,
        String targetHost,
        int targetPort,
        int publishedPort,
        String path,
        boolean enabled,
        String visibility,
        java.util.List<Long> allowedClientIds,
        String publishedAddress,
        List<PeerMeshSharedServiceInstanceView> instances,
        String createdAt,
        String updatedAt
) {
    public record PeerMeshSharedServiceInstanceView(
            long publisherSessionId,
            String instanceId,
            boolean online,
            boolean advertised,
            long revision,
            String lastReportedAt,
            String expiresAt,
            PeerAdvertisedService service,
            long bytesIn,
            long bytesOut,
            int activeConnections,
            long totalConnections
    ) {
    }
}
