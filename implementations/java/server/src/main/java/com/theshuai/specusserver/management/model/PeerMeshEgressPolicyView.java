package com.theshuai.specusserver.management.model;

import com.theshuai.common.peeregress.PeerEgressPolicy;

import java.util.List;

/**
 * Management projection of an egress policy.
 *
 * <p>{@code effectiveConsumerClientIds} is the configured allowlist already intersected with the
 * base Peer ACL, so an operator can see at a glance which devices the policy actually grants rather
 * than which ones it names.
 */
public record PeerMeshEgressPolicyView(
        long id,
        long egressClientId,
        String egressClientName,
        boolean enabled,
        String scope,
        List<Long> allowedConsumerClientIds,
        List<Long> effectiveConsumerClientIds,
        List<PeerEgressPolicy.PeerEgressDestinationRule> destinationRules,
        int maxConcurrentFlows,
        int maxFlowsPerConsumer,
        int idleTimeoutSeconds,
        String createdAt,
        String updatedAt) {
}
