package com.theshuai.common.peeregress;

import java.util.ArrayList;
import java.util.List;

/**
 * Egress authorization, per {@code protocol/spec/peer-egress.md}.
 *
 * <p>The checks run in a fixed order so that implementations agree on which code a request fails
 * with, not merely on allow versus deny. Shared vectors:
 * {@code protocol/test-vectors/peer-egress-authz-v1.json}, and for a flow that carries a name
 * {@code protocol/test-vectors/peer-egress-domain-policy-v1.json}.
 */
public final class PeerEgressAuthorization {
    /**
     * Destinations that stay denied no matter what the policy says. A rule as broad as
     * {@code 0.0.0.0/0} must not reach loopback, link-local, cloud metadata, multicast, broadcast
     * or the mesh itself, so this list is consulted before any destination rule.
     */
    public static final List<String> FORCED_DENY_CIDRS = List.of(
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4",
            // Covered by 240.0.0.0/4, listed so the broadcast address is explicit to a reader.
            "255.255.255.255/32");

    /** Well-known instance metadata endpoints, denied independently of the link-local block. */
    public static final List<String> CLOUD_METADATA_CIDRS = List.of(
            "169.254.169.254/32",
            "100.100.100.200/32");

    /** RFC 1918 private use plus RFC 6598 shared address space. */
    public static final List<String> LAN_CIDRS = List.of(
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10");

    public record Decision(boolean allowed, String code) {
        public static Decision deny(String code) {
            return new Decision(false, code);
        }

        public static Decision allow() {
            return new Decision(true, PeerEgressCodes.ALLOWED);
        }
    }

    /**
     * Deployment-wide additions to the forced-deny list.
     *
     * @param meshCidr             the Peer Mesh virtual network
     * @param deploymentDenyCidrs  control, STUN and TURN endpoint addresses for this deployment
     */
    public record Context(String meshCidr, List<String> deploymentDenyCidrs) {
        public static Context defaults() {
            return new Context(PeerEgressRules.DEFAULT_MESH_CIDR, List.of());
        }
    }

    private PeerEgressAuthorization() {
    }

    public static Decision evaluate(PeerEgressRequest request,
                                    PeerEgressPolicy policy,
                                    boolean peerAclAllows,
                                    Context context) {
        if (request == null || policy == null) {
            return Decision.deny(PeerEgressCodes.DEST_DENIED);
        }
        Context effective = context == null ? Context.defaults() : context;

        if (request.isHop()) {
            return Decision.deny(PeerEgressCodes.HOP_NOT_ALLOWED);
        }
        if (!policy.isEnabled()) {
            return Decision.deny(PeerEgressCodes.DISABLED);
        }
        if (!peerAclAllows) {
            return Decision.deny(PeerEgressCodes.PEER_ACL_DENIED);
        }
        List<Long> consumers = policy.getAllowedConsumerClientIds();
        if (consumers == null || !consumers.contains(request.getConsumerClientId())) {
            return Decision.deny(PeerEgressCodes.CONSUMER_DENIED);
        }

        Integer destination = Ipv4Cidr.parseAddress(request.getDestinationIp());
        if (destination == null) {
            return Decision.deny(PeerEgressCodes.DEST_DENIED);
        }
        if (containedIn(destination, forcedDenyFor(effective, request))) {
            return Decision.deny(PeerEgressCodes.FORBIDDEN_DESTINATION);
        }

        String scope = containedIn(destination, LAN_CIDRS)
                ? PeerEgressPolicy.SCOPE_LAN
                : PeerEgressPolicy.SCOPE_PUBLIC;
        if (!scope.equals(policy.getScope())) {
            return Decision.deny(PeerEgressCodes.SCOPE_DENIED);
        }

        // The destination, protocol and port steps look at the destination rules that contain the
        // address together with, for a flow that carries a name, the domain rules that cover it.
        // A domain rule can only add to what the destination rules allow, never narrow it.
        List<Grant> matches = new ArrayList<>();
        List<PeerEgressPolicy.PeerEgressDestinationRule> rules = policy.getDestinationRules();
        if (rules != null) {
            for (PeerEgressPolicy.PeerEgressDestinationRule rule : rules) {
                Ipv4Cidr cidr = rule == null ? null : Ipv4Cidr.parse(rule.getCidr());
                if (cidr != null && cidr.contains(destination)) {
                    matches.add(new Grant(rule.getProtocols(), rule.getPortRanges()));
                }
            }
        }
        matches.addAll(domainMatches(policy.getDomainRules(), request.getName()));
        if (matches.isEmpty()) {
            return Decision.deny(PeerEgressCodes.DEST_DENIED);
        }

        String protocol = request.getProtocol() == null ? "" : request.getProtocol();
        List<Grant> protocolMatches = matches.stream()
                .filter(grant -> grant.protocols() != null && grant.protocols().contains(protocol))
                .toList();
        if (protocolMatches.isEmpty()) {
            return Decision.deny(PeerEgressCodes.PROTOCOL_DENIED);
        }

        if (!portAllowed(protocolMatches, request.getDestinationPort())) {
            return Decision.deny(PeerEgressCodes.PORT_DENIED);
        }

        PeerEgressPolicy.PeerEgressLimits limits = policy.getLimits();
        if (limits != null) {
            if (request.getActiveFlowsForConsumer() >= limits.getMaxFlowsPerConsumer()
                    || request.getActiveFlowsTotal() >= limits.getMaxConcurrentFlows()) {
                return Decision.deny(PeerEgressCodes.LIMIT_EXCEEDED);
            }
        }
        return Decision.allow();
    }

    private static List<String> forcedDenyFor(Context context, PeerEgressRequest request) {
        List<String> denied = new ArrayList<>(FORCED_DENY_CIDRS);
        denied.addAll(CLOUD_METADATA_CIDRS);
        denied.add(context.meshCidr() == null || context.meshCidr().isBlank()
                ? PeerEgressRules.DEFAULT_MESH_CIDR
                : context.meshCidr());
        if (context.deploymentDenyCidrs() != null) {
            denied.addAll(context.deploymentDenyCidrs());
        }
        if (request.getLocalInterfaceCidrs() != null) {
            denied.addAll(request.getLocalInterfaceCidrs());
        }
        return denied;
    }

    private static boolean containedIn(int address, List<String> cidrs) {
        for (String text : cidrs) {
            Ipv4Cidr cidr = Ipv4Cidr.parse(text);
            if (cidr != null && cidr.contains(address)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The domain rules covering a flow's name, or none for a flow without one. A flow that arrived
     * by address is never admitted by a domain rule, even when its address is what an allowed name
     * resolves to: that would turn a grant of a name into a grant of an address.
     *
     * <p>A match that is not a well-formed name or {@code *.name} grants nothing. The decoder
     * already drops such entries; checking again keeps a policy assembled some other way from
     * granting {@code *.com} or {@code *}.
     */
    private static List<Grant> domainMatches(List<PeerEgressPolicy.PeerEgressDomainRule> rules, String name) {
        if (rules == null || rules.isEmpty() || name == null) {
            return List.of();
        }
        String normalized = PeerEgressNames.normalize(name);
        if (normalized.isEmpty()) {
            return List.of();
        }
        List<Grant> covering = new ArrayList<>();
        for (PeerEgressPolicy.PeerEgressDomainRule rule : rules) {
            if (rule != null && PeerEgressNames.validMatch(rule.getMatch())
                    && PeerEgressNames.coverage(rule.getMatch(), normalized) >= 0) {
                covering.add(new Grant(rule.getProtocols(), rule.getPortRanges()));
            }
        }
        return covering;
    }

    /** What a matching destination or domain rule grants: its protocols and its ports. */
    private record Grant(List<String> protocols, List<List<Integer>> portRanges) {
    }

    private static boolean portAllowed(List<Grant> grants, int port) {
        for (Grant grant : grants) {
            List<List<Integer>> ranges = grant.portRanges();
            if (ranges == null) {
                continue;
            }
            for (List<Integer> range : ranges) {
                if (range != null && range.size() == 2
                        && range.get(0) != null && range.get(1) != null
                        && port >= range.get(0) && port <= range.get(1)) {
                    return true;
                }
            }
        }
        return false;
    }
}
