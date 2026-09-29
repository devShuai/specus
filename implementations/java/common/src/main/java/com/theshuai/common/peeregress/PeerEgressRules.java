package com.theshuai.common.peeregress;

import java.util.List;

/**
 * Consumer rule validation and matching, per {@code protocol/spec/peer-egress.md}.
 *
 * <p>Shared vectors: {@code protocol/test-vectors/peer-egress-rules-v1.json}.
 */
public final class PeerEgressRules {
    /** Default Peer Mesh virtual network; deployments overriding the CIDR pass their own. */
    public static final String DEFAULT_MESH_CIDR = "100.96.0.0/11";

    private PeerEgressRules() {
    }

    /**
     * Result of matching a destination against an ordered rule list.
     *
     * @param matchedRuleIndex index of the winning rule, or {@code null} when nothing matched
     */
    public record Match(String action, Integer matchedRuleIndex, Long egressClientId) {
        public static Match unmatched() {
            return new Match(PeerEgressRule.ACTION_DIRECT, null, null);
        }

        public boolean matched() {
            return matchedRuleIndex != null;
        }
    }

    /** The {@code kind} a rule reports in the status: what its match is. */
    public static final String KIND_CIDR = "cidr";
    public static final String KIND_DOMAIN = "domain";

    /**
     * Returns the failing code, or {@code null} when the rule is acceptable, with phase two not
     * running: a domain rule is refused as unsupported, word for word as in phase one.
     *
     * <p>The checks run in a fixed order so that every implementation reports the same code for a
     * rule that violates more than one constraint.
     */
    public static String validate(PeerEgressRule rule, String meshCidr) {
        return validate(rule, meshCidr, null);
    }

    /**
     * As above, with the fake-IP pool while phase two runs ({@code protocol/spec/peer-egress-dns.md}),
     * or null while it does not. Running, a well-formed domain rule is accepted and an address rule
     * reaching into the pool is refused: an address in the pool means whatever name it was handed out
     * for, so only a domain rule may decide where it goes.
     *
     * <p>The order is phase one's with phase two's checks in the places the shared vector pins:
     * a domain match is checked where phase one refused it, the pool after the mesh.
     */
    public static String validate(PeerEgressRule rule, String meshCidr, String fakeIpCidr) {
        if (rule == null) {
            return PeerEgressCodes.RULE_MALFORMED;
        }
        // Ahead of anything about the rule's content: a switched-off rule is the user's choice, and
        // should not have to be fixed before it may sit in the list.
        if (rule.switchedOff()) {
            return PeerEgressCodes.RULE_DISABLED;
        }
        String match = rule.getMatch() == null ? "" : rule.getMatch().trim();
        if (match.isEmpty()) {
            return PeerEgressCodes.RULE_MALFORMED;
        }
        if (match.indexOf(':') >= 0) {
            return PeerEgressCodes.RULE_IPV6_UNSUPPORTED;
        }
        Ipv4Cidr pool = fakeIpCidr == null ? null : Ipv4Cidr.parse(fakeIpCidr);
        boolean phaseTwo = fakeIpCidr != null;
        if (looksLikeDomain(match)) {
            if (!phaseTwo) {
                return PeerEgressCodes.RULE_DOMAIN_UNSUPPORTED;
            }
            // Neither an address nor a name (1.2.3.4-5 names nothing) is malformed, as an address
            // that failed to parse would be.
            if (!PeerEgressNames.validMatch(match)) {
                return PeerEgressCodes.RULE_MALFORMED;
            }
        } else {
            Ipv4Cidr cidr = Ipv4Cidr.parse(match);
            if (cidr == null) {
                return PeerEgressCodes.RULE_MALFORMED;
            }
            if (cidr.prefixLength() == 0) {
                // This version never takes over the default route: doing so would override the
                // user's existing configuration and contradict "unmatched traffic stays local".
                return PeerEgressCodes.RULE_DEFAULT_ROUTE;
            }
            Ipv4Cidr mesh = Ipv4Cidr.parse(meshCidr == null || meshCidr.isBlank() ? DEFAULT_MESH_CIDR : meshCidr);
            if (mesh != null && cidr.overlaps(mesh)) {
                return PeerEgressCodes.RULE_MESH_OVERLAP;
            }
            if (pool != null && cidr.overlaps(pool)) {
                return PeerEgressCodes.RULE_FAKE_IP_OVERLAP;
            }
        }
        if (rule.getPort() != null) {
            return PeerEgressCodes.RULE_PORT_UNSUPPORTED;
        }
        String action = rule.getAction() == null ? "" : rule.getAction().trim();
        if (!PeerEgressRule.ACTION_EGRESS.equals(action)
                && !PeerEgressRule.ACTION_DIRECT.equals(action)
                && !PeerEgressRule.ACTION_BLOCK.equals(action)) {
            return PeerEgressCodes.RULE_MALFORMED;
        }
        if (PeerEgressRule.ACTION_EGRESS.equals(action)
                && (rule.getEgressClientId() == null || rule.getEgressClientId() <= 0)) {
            // The field being present is not the same as it being usable. Zero is this project's
            // sentinel for "no consumer", so accepting it would let the rule pass validation,
            // install its route, and then fail to find a peer for every packet: a configuration
            // error deferred into a runtime blackhole.
            return PeerEgressCodes.RULE_MISSING_TARGET;
        }
        return null;
    }

    /**
     * Longest prefix wins; when two rules share a prefix length the earlier one wins.
     *
     * <p>An unmatched destination resolves to {@code direct}. That is the routing table's own
     * behaviour rather than a fallback branch: a destination with no installed route never reaches
     * the tunnel device in the first place.
     *
     * <p>Rules that fail validation are skipped, which is why the mesh prefix is needed here.
     * Skipped rather than left to the caller to pre-filter, so that one bad rule cannot change
     * what a good one decides no matter who assembled the list: a refused rule with a longer
     * prefix would otherwise go on outranking a legal one, and what the operator was told was
     * refused would not match where the traffic actually goes.
     */
    public static Match match(List<PeerEgressRule> rules, String destination, String meshCidr) {
        return match(rules, destination, meshCidr, null);
    }

    /**
     * As above while phase two runs with the given pool (null when it does not). Domain rules never
     * match an address, and an address rule the pool refuses takes no part, like any refused rule.
     */
    public static Match match(List<PeerEgressRule> rules, String destination, String meshCidr, String fakeIpCidr) {
        Integer address = Ipv4Cidr.parseAddress(destination);
        if (address == null || rules == null || rules.isEmpty()) {
            return Match.unmatched();
        }
        PeerEgressRule best = null;
        int bestIndex = -1;
        int bestPrefix = -1;
        for (int index = 0; index < rules.size(); index++) {
            PeerEgressRule rule = rules.get(index);
            if (validate(rule, meshCidr, fakeIpCidr) != null || isDomain(rule)) {
                continue;
            }
            Ipv4Cidr cidr = Ipv4Cidr.parse(rule.getMatch());
            if (cidr == null || !cidr.contains(address)) {
                continue;
            }
            if (cidr.prefixLength() > bestPrefix) {
                best = rule;
                bestIndex = index;
                bestPrefix = cidr.prefixLength();
            }
        }
        if (best == null) {
            return Match.unmatched();
        }
        Long target = PeerEgressRule.ACTION_EGRESS.equals(best.getAction()) ? best.getEgressClientId() : null;
        return new Match(best.getAction(), bestIndex, target);
    }

    /**
     * Whether a rule's match is a domain rather than an address, which is the {@code kind} the
     * status reports. Anything with a colon is an (IPv6) address, whatever letters it carries.
     */
    public static boolean isDomain(PeerEgressRule rule) {
        String match = rule == null || rule.getMatch() == null ? "" : rule.getMatch().trim();
        return !match.isEmpty() && match.indexOf(':') < 0 && looksLikeDomain(match);
    }

    /** {@link #KIND_DOMAIN} or {@link #KIND_CIDR}. */
    public static String kind(PeerEgressRule rule) {
        return isDomain(rule) ? KIND_DOMAIN : KIND_CIDR;
    }

    private static boolean looksLikeDomain(String match) {
        for (int i = 0; i < match.length(); i++) {
            char c = match.charAt(i);
            boolean digitOrSeparator = (c >= '0' && c <= '9') || c == '.' || c == '/';
            if (!digitOrSeparator) {
                return true;
            }
        }
        return false;
    }
}
