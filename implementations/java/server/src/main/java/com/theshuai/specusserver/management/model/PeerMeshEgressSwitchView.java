package com.theshuai.specusserver.management.model;

/**
 * Management projection of the tenant-wide egress switch.
 *
 * <p>The three flags are reported separately so an operator can tell why egress is off: the
 * deployment never enabled Peer Mesh, the tenant switch is down, or both are on and it is the
 * per-device policies that grant nothing.
 */
public record PeerMeshEgressSwitchView(
        boolean deploymentEnabled,
        boolean configuredEnabled,
        boolean effectiveEnabled,
        int protocolVersion,
        int enabledPolicyCount,
        String updatedAt,
        String updatedBy) {
}
