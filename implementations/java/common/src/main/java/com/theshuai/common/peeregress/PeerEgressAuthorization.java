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

    /**
     * The IPv6 counterparts of {@link #FORCED_DENY_CIDRS} ({@code protocol/spec/peer-egress.md},
     * 强制拒绝清单). A destination is checked against both lists; only a prefix of its own family can
     * contain it.
     */
    public static final List<String> FORCED_DENY_CIDRS6 = List.of(
            "::/128",
            "::1/128",
            // A socket connected to an IPv4-mapped address reaches the IPv4 address, past every
            // IPv4 entry.
            "::ffff:0:0/96",
            // Prefixes that embed an IPv4 address a NAT64 gateway or a 6to4 relay forwards to,
            // metadata and private ranges included.
            "64:ff9b::/96",
            "64:ff9b:1::/48",
            "2002::/16",
            "fe80::/10",
            "fec0::/10",
            "ff00::/8");

    /** The IPv6 instance metadata endpoint, in the unique local range a LAN policy can grant. */
    public static final List<String> CLOUD_METADATA_CIDRS6 = List.of(
            "fd00:ec2::254/128");

    /** Unique local addresses, the IPv6 counterpart of the private ranges. */
    public static final List<String> LAN_CIDRS6 = List.of(
            "fc00::/7");

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

        Target destination = Target.parse(request.getDestinationIp());
        if (destination == null) {
            return Decision.deny(PeerEgressCodes.DEST_DENIED);
        }
        if (destination.in(forcedDenyFor(effective, request))) {
            return Decision.deny(PeerEgressCodes.FORBIDDEN_DESTINATION);
        }

        String scope = destination.in(LAN_CIDRS) || destination.in(LAN_CIDRS6)
                ? PeerEgressPolicy.SCOPE_LAN
                : PeerEgressPolicy.SCOPE_PUBLIC;
        if (!scope.equals(policy.getScope())) {
            return Decision.deny(PeerEgressCodes.SCOPE_DENIED);
        }

        // The destination, protocol and port steps look at the destination rules that contain the
        // address together with, for a flow that carries a name, the domain rules that cover it.
        // A domain rule can only add to what the destination rules allow, never narrow it.
        // A rule covers addresses of its own family only: 0.0.0.0/0 grants no IPv6 address and ::/0
        // no IPv4 one.
        List<Grant> matches = new ArrayList<>();
        List<PeerEgressPolicy.PeerEgressDestinationRule> rules = policy.getDestinationRules();
        if (rules != null) {
            for (PeerEgressPolicy.PeerEgressDestinationRule rule : rules) {
                if (rule != null && rule.getCidr() != null && destination.in(List.of(rule.getCidr()))) {
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
        denied.addAll(FORCED_DENY_CIDRS6);
        denied.addAll(CLOUD_METADATA_CIDRS6);
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

    /** A destination as the judgment reads it, IPv4 or IPv6 ({@code v6} null for IPv4). */
    private record Target(int v4, long[] v6) {
        /** IPv6 when the text has a colon, with the spelling the rules use; IPv4 otherwise. Null if neither. */
        static Target parse(String text) {
            if (text != null && text.indexOf(':') >= 0) {
                long[] address = Ipv6Cidr.parseAddress(text);
                return address == null ? null : new Target(0, address);
            }
            Integer address = Ipv4Cidr.parseAddress(text);
            return address == null ? null : new Target(address, null);
        }

        /**
         * Whether a prefix of the target's own family in the list contains it. Prefixes of the other
         * family, and anything that does not read, are passed over: a list can mix both.
         */
        boolean in(List<String> cidrs) {
            if (v6 == null) {
                return containedIn(v4, cidrs);
            }
            for (String text : cidrs) {
                String trimmed = text == null ? "" : text.trim();
                if (trimmed.indexOf(':') < 0) {
                    continue;
                }
                Ipv6Cidr cidr = Ipv6Cidr.parse(trimmed);
                if (cidr != null && cidr.contains(v6)) {
                    return true;
                }
            }
            return false;
        }
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
