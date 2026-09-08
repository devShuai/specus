package com.theshuai.specusserver.management.model;

import java.util.Map;

/**
 * Management projection of one egress device's latest self-report.
 *
 * <p>{@code online} is resolved from the live control channel rather than from the report, so a
 * node that stopped reporting is shown as offline instead of frozen at its last counters.
 */
public record PeerMeshEgressActivityView(
        long egressClientId,
        String egressClientName,
        boolean online,
        long revision,
        long activeFlows,
        long totalFlows,
        Map<String, Long> rejectedFlows,
        long bytesIn,
        long bytesOut,
        String reportedAt) {
}
