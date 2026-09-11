package com.theshuai.common.peeregress;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.List;

/**
 * Egress-side authorization policy, owned by the server and pushed as {@code egress-config}.
 *
 * <p>Base Peer Mesh access does not imply egress access. The server intersects this policy with the
 * base Peer ACL before pushing it, and the egress node evaluates it again before every
 * {@code connect()}.
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PeerEgressPolicy {
    public static final String SCOPE_PUBLIC = "PUBLIC";
    public static final String SCOPE_LAN = "LAN";

    private Long egressClientId;

    /** Off by default. A deployment that has never configured egress must not forward anything. */
    private boolean enabled;

    private List<Long> allowedConsumerClientIds = List.of();

    /**
     * No default. Scope is an authorization dimension, so a policy that never names one must deny
     * rather than fall back to the permissive value: {@code PUBLIC} would let a policy assembled
     * without a scope reach the whole internet.
     */
    private String scope = "";

    /** Empty means deny everything. There is no "unconfigured therefore open" state. */
    private List<PeerEgressDestinationRule> destinationRules = List.of();

    private PeerEgressLimits limits = new PeerEgressLimits();

    @Data
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PeerEgressDestinationRule {
        private String cidr;
        private List<String> protocols = List.of();
        /** Inclusive {@code [low, high]} pairs. */
        private List<List<Integer>> portRanges = List.of();
    }

    @Data
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PeerEgressLimits {
        private int maxConcurrentFlows = 256;
        private int maxFlowsPerConsumer = 64;
        private int idleTimeoutSeconds = 60;
    }
}
