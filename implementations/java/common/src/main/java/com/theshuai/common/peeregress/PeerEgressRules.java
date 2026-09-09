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

    /**
     * Returns the failing code, or {@code null} when the rule is acceptable.
     *
     * <p>The checks run in a fixed order so that every implementation reports the same code for a
     * rule that violates more than one constraint.
     */
    public static String validate(PeerEgressRule rule, String meshCidr) {
        if (rule == null) {
            return PeerEgressCodes.RULE_MALFORMED;
        }
        String match = rule.getMatch() == null ? "" : rule.getMatch().trim();
        if (match.isEmpty()) {
            return PeerEgressCodes.RULE_MALFORMED;
        }
        if (match.indexOf(':') >= 0) {
            return PeerEgressCodes.RULE_IPV6_UNSUPPORTED;
        }
        if (looksLikeDomain(match)) {
            return PeerEgressCodes.RULE_DOMAIN_UNSUPPORTED;
        }
        Ipv4Cidr cidr = Ipv4Cidr.parse(match);
        if (cidr == null) {
            return PeerEgressCodes.RULE_MALFORMED;
        }
        if (cidr.prefixLength() == 0) {
            // This version never takes over the default route: doing so would override the user's
            // existing configuration and contradict "unmatched traffic stays local".
            return PeerEgressCodes.RULE_DEFAULT_ROUTE;
        }
        Ipv4Cidr mesh = Ipv4Cidr.parse(meshCidr == null || meshCidr.isBlank() ? DEFAULT_MESH_CIDR : meshCidr);
        if (mesh != null && cidr.overlaps(mesh)) {
            return PeerEgressCodes.RULE_MESH_OVERLAP;
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
        if (PeerEgressRule.ACTION_EGRESS.equals(action) && rule.getEgressClientId() == null) {
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
     */
    public static Match match(List<PeerEgressRule> rules, String destination) {
        Integer address = Ipv4Cidr.parseAddress(destination);
        if (address == null || rules == null || rules.isEmpty()) {
            return Match.unmatched();
        }
        PeerEgressRule best = null;
        int bestIndex = -1;
        int bestPrefix = -1;
        for (int index = 0; index < rules.size(); index++) {
            PeerEgressRule rule = rules.get(index);
            Ipv4Cidr cidr = rule == null ? null : Ipv4Cidr.parse(rule.getMatch());
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
