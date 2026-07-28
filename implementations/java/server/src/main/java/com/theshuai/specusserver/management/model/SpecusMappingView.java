package com.theshuai.specusserver.management.model;

public record SpecusMappingView(
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
