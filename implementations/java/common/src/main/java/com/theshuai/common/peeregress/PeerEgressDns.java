package com.theshuai.common.peeregress;

import java.util.List;
import java.util.function.LongPredicate;

/**
 * Phase two of peer egress on the consumer: when it runs, which domain rule a name selects, and
 * which rules the status reports in force. See {@code protocol/spec/peer-egress-dns.md}; the same
 * decisions as the Go and .NET clients, checked against
 * {@code protocol/test-vectors/peer-egress-dns-v1.json}.
 */
public final class PeerEgressDns {
    /** {@code peerEgressFakeIpCidr} when the configuration names none. */
    public static final String DEFAULT_FAKE_IP_CIDR = "198.18.0.0/15";
    /** The narrowest and widest pool accepted. */
    public static final int MIN_POOL_PREFIX = 8;
    public static final int MAX_POOL_PREFIX = 24;
    /**
     * A mapping used within this long is never reclaimed. Unrelated to the answer's TTL of one
     * second: how long an application caches an address is not ours to decide.
     */
    public static final long MIN_MAPPING_LIFETIME_MS = 6 * 3600 * 1000L;
    /** An evicted address is handed to no other name for this long, so old connections miss. */
    public static final long QUARANTINE_MS = 30 * 60 * 1000L;

    private PeerEgressDns() {
    }

    /**
     * Null when {@code peerEgressFakeIpCidr} is usable: IPv4, host bits zero, {@code /8} to
     * {@code /24}, clear of the mesh. Overlap with this device's interfaces is the caller's check,
     * at startup; it is not something a vector can hold.
     */
    public static String poolProblem(String cidr, String meshCidr) {
        Ipv4Cidr pool = Ipv4Cidr.parse(cidr == null ? "" : cidr.trim());
        if (pool == null || pool.prefixLength() < MIN_POOL_PREFIX || pool.prefixLength() > MAX_POOL_PREFIX) {
            return PeerEgressCodes.FAKE_IP_POOL_INVALID;
        }
        Ipv4Cidr mesh = Ipv4Cidr.parse(meshCidr == null || meshCidr.isBlank()
                ? PeerEgressRules.DEFAULT_MESH_CIDR : meshCidr.trim());
        if (mesh != null && pool.overlaps(mesh)) {
            return PeerEgressCodes.FAKE_IP_POOL_INVALID;
        }
        return null;
    }

    /**
     * Whether phase two runs, and when it was asked for and cannot, why.
     *
     * @param code {@link PeerEgressCodes#FAKE_IP_POOL_INVALID} when both switches are on and the
     *             pool is not usable; null otherwise, including when a switch is simply off
     */
    public record PhaseTwo(boolean active, String code) {
        public static PhaseTwo off() {
            return new PhaseTwo(false, null);
        }
    }

    /**
     * Phase two runs when it is asked for on top of phase one and the pool is usable. An unusable
     * pool stops phase two alone: phase one carries on, and domain rules read as though takeover
     * were off.
     */
    public static PhaseTwo phaseTwo(boolean consumerEnabled, boolean takeover, String cidr, String meshCidr) {
        if (!consumerEnabled || !takeover) {
            return PhaseTwo.off();
        }
        String code = poolProblem(cidr, meshCidr);
        return new PhaseTwo(code == null, code);
    }

    /**
     * The pool a configuration would run phase two with, judged as the configuration stands: the
     * takeover switch on and the pool usable against the default mesh. The consumer's master switch
     * is not part of it, so a rule is judged on its own before takeover is turned on. Null when
     * phase two would not run.
     */
    public static String configuredPool(boolean takeover, String cidr) {
        if (!takeover || poolProblem(cidr, PeerEgressRules.DEFAULT_MESH_CIDR) != null) {
            return null;
        }
        return cidr.trim();
    }

    /**
     * The index of the domain rule that claims a name, or null when none does.
     *
     * <p>Exact beats suffix, a suffix with more labels beats one with fewer, and of equals the
     * earlier wins. Refused rules take no part, as in phase one, with one exception that is not a
     * refusal at all: a rule whose egress cannot resolve names is out of force in the status but
     * still claims its names, because that is the egress's state at the moment rather than the rule
     * being wrong, and letting the name fall back to local resolution would be the leak.
     *
     * @param fakeIpCidr the pool phase two runs with; null selects nothing, as no domain rule is
     *                   valid while phase two does not run
     */
    public static Integer selectDomainRule(List<PeerEgressRule> rules, String name, String meshCidr,
            String fakeIpCidr) {
        if (rules == null || fakeIpCidr == null) {
            return null;
        }
        String query = PeerEgressNames.normalize(name);
        Integer best = null;
        int bestRank = -1;
        for (int index = 0; index < rules.size(); index++) {
            PeerEgressRule rule = rules.get(index);
            if (!PeerEgressRules.isDomain(rule) || PeerEgressRules.validate(rule, meshCidr, fakeIpCidr) != null) {
                continue;
            }
            int rank = PeerEgressNames.coverage(rule.getMatch(), query);
            if (rank < 0) {
                continue;
            }
            if (best == null || rank < bestRank) {
                best = index;
                bestRank = rank;
            }
        }
        return best;
    }

    /**
     * The code the status gives a rule, null when it is in force: the validation, then the
     * capability of the rule's egress.
     *
     * <p>The capability only counts for an egress that is online. The catalogue says false for an
     * offline one, and a rule to an offline egress is right and waiting, which is phase one's
     * {@code egress-unavailable}, not a rule pointed at a device that can never take it.
     */
    public static String ruleStatus(PeerEgressRule rule, String meshCidr, String fakeIpCidr,
            LongPredicate online, LongPredicate domainCapable) {
        String code = PeerEgressRules.validate(rule, meshCidr, fakeIpCidr);
        if (code != null) {
            return code;
        }
        if (PeerEgressRules.isDomain(rule) && PeerEgressRule.ACTION_EGRESS.equals(rule.getAction().trim())) {
            long egress = rule.getEgressClientId();
            if (online.test(egress) && !domainCapable.test(egress)) {
                return PeerEgressCodes.RULE_EGRESS_NO_DOMAIN;
            }
        }
        return null;
    }
}
