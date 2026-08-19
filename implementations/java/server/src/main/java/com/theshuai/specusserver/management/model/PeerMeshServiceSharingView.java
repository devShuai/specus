package com.theshuai.specusserver.management.model;

public record PeerMeshServiceSharingView(
        boolean deploymentEnabled,
        boolean configuredEnabled,
        boolean effectiveEnabled,
        int peerServiceDiscoveryVersion,
        java.util.List<String> supportedApplications,
        int enabledServiceCount,
        String updatedAt,
        String updatedBy,
        boolean mdnsImportEnabled
) {
}
