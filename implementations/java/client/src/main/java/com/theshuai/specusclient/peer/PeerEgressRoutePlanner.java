package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turning consumer rules into routes.
 *
 * <p>Only exact prefixes are installed, and the planner invents none of its own: no default route,
 * and no {@code 0.0.0.0/1} plus {@code 128.0.0.0/1} pair standing in for one. A tool that captures
 * everything cannot be reasoned about by the person running it, and "unmatched traffic stays local"
 * stops being true the moment something covers all of it.
 *
 * <p>Validation refuses only {@code /0}, though. An operator who writes those two halves by hand
 * still gets near-total capture, and the lower one is refused today only because it happens to
 * contain the mesh. Closing that means picking a minimum prefix length, which is a policy decision
 * rather than something to settle while porting.
 *
 * <p>The planner is pure. It says which routes should exist; the installer performs the difference
 * and can undo it. Splitting them is what lets rollback, conflict refusal and ownership be tested
 * without touching a real routing table.
 *
 * <p>Shared vector: {@code protocol/test-vectors/peer-egress-routes-v1.json}.
 */
public final class PeerEgressRoutePlanner {

    private PeerEgressRoutePlanner() {
    }

    /** What a route is for. */
    public enum Kind {
        /** Sends a prefix into the TUN for the data plane to handle. */
        TUN("tun"),
        /**
         * Pins one address to the physical path.
         *
         * <p>The control connection, STUN and TURN, peer UDP endpoints and the egress peer's own
         * address have to keep working over the real network. If a rule's prefix happened to
         * contain one of them, its traffic would be routed into the tunnel that carries it, and
         * the tunnel would be carrying its own transport.
         */
        BYPASS("bypass");

        private final String wireName;

        Kind(String wireName) {
            this.wireName = wireName;
        }

        /** The name used in the journal and in the shared vector. */
        public String wireName() {
            return wireName;
        }

        public static Kind fromWireName(String name) {
            return BYPASS.wireName.equals(name) ? BYPASS : TUN;
        }
    }

    /**
     * One entry this feature wants to own.
     *
     * @param cidr   normalised, so the same route is never described two ways
     * @param origin what asked for this route, for the conflict message an operator reads
     */
    public record Route(String cidr, Kind kind, String origin) {
    }

    /** A rule that was refused, paired with its code, so every problem is reported at once. */
    public record Refusal(int index, String match, String code) {
    }

    /** The planner's answer: what to own, and which rules were thrown out getting there. */
    public record Plan(List<Route> routes, List<Refusal> refused) {
    }

    /** What to withdraw and what to add to move from one set to another. */
    public record Difference(List<Route> remove, List<Route> add) {
    }

    /**
     * Works out the routes a rule set and a bypass set need.
     *
     * <p>Refused rules are returned rather than skipped silently: a rule an operator wrote and
     * this feature ignored is a leak they have no way to notice.
     *
     * <p>The bypass list comes from runtime discovery rather than from configuration, so an entry
     * that cannot be read is skipped. Refusing the whole plan over one would stop every rule
     * because a single peer went away.
     */
    public static Plan plan(List<PeerEgressRule> rules, List<String> bypass, String meshCidr) {
        List<PeerEgressRule> ruleList = rules == null ? List.of() : rules;
        List<Refusal> refused = new ArrayList<>();
        Set<Integer> skip = new LinkedHashSet<>();
        for (int index = 0; index < ruleList.size(); index++) {
            PeerEgressRule rule = ruleList.get(index);
            String code = PeerEgressRules.validate(rule, meshCidr);
            if (code != null) {
                refused.add(new Refusal(index, rule == null ? "" : rule.getMatch(), code));
                skip.add(index);
            }
        }

        Set<String> seen = new LinkedHashSet<>();
        List<Route> routes = new ArrayList<>();

        // Bypass first: these are the addresses that must not be captured under any rule, and
        // adding them first means a rule naming the same prefix cannot displace one.
        for (String endpoint : bypass == null ? List.<String>of() : bypass) {
            Integer address = Ipv4Cidr.parseAddress(endpoint == null ? null : endpoint.trim());
            if (address == null) {
                continue;
            }
            String cidr = Ipv4Cidr.format(address) + "/32";
            if (seen.add(cidr)) {
                routes.add(new Route(cidr, Kind.BYPASS, "bypass"));
            }
        }

        for (int index = 0; index < ruleList.size(); index++) {
            if (skip.contains(index)) {
                continue;
            }
            PeerEgressRule rule = ruleList.get(index);
            // A direct rule installs nothing. Traffic stays local by not having a route, which is
            // the same mechanism that makes unmatched traffic local, so there is one behaviour
            // rather than two that have to agree.
            //
            // A block rule does install one: the packet has to be captured before it can be
            // dropped, and the data plane is what drops it.
            String action = rule.getAction() == null ? "" : rule.getAction().trim();
            if (!PeerEgressRule.ACTION_EGRESS.equals(action) && !PeerEgressRule.ACTION_BLOCK.equals(action)) {
                continue;
            }
            Ipv4Cidr cidr = Ipv4Cidr.parse(rule.getMatch());
            if (cidr == null) {
                continue;
            }
            // Rendered the one way this feature writes a prefix, so a route installed in one run
            // is recognised as the same route in the next.
            String normalised = cidr.toString();
            if (!seen.add(normalised)) {
                // Two rules over the same prefix need one route; the engine decides between them
                // per packet, and installing the prefix twice would make removal ambiguous.
                continue;
            }
            routes.add(new Route(normalised, Kind.TUN, "rule:" + rule.getMatch()));
        }

        sort(routes);
        return new Plan(routes, refused);
    }

    /**
     * Orders bypass entries first, then by prefix.
     *
     * <p>Bypass first because installation happens in this order: the addresses that keep the
     * tunnel's own transport working are in place before anything is pointed into the tunnel.
     * Deterministic order also means the journal and every log line read the same way run to run.
     */
    public static void sort(List<Route> routes) {
        routes.sort(PeerEgressRoutePlanner::compare);
    }

    private static int compare(Route left, Route right) {
        int order = Integer.compare(rank(left.kind()), rank(right.kind()));
        if (order != 0) {
            return order;
        }
        Ipv4Cidr leftCidr = Ipv4Cidr.parse(left.cidr());
        Ipv4Cidr rightCidr = Ipv4Cidr.parse(right.cidr());
        if (leftCidr == null || rightCidr == null) {
            // Falls back to text, so the ordering stays total on data the planner would never
            // have produced rather than throwing where a sort is expected to succeed.
            return left.cidr().compareTo(right.cidr());
        }
        // Addresses are unsigned; comparing them as signed ints would order 10.x above 200.x.
        order = Integer.compareUnsigned(leftCidr.network(), rightCidr.network());
        return order != 0 ? order : Integer.compare(leftCidr.prefixLength(), rightCidr.prefixLength());
    }

    private static int rank(Kind kind) {
        return kind == Kind.BYPASS ? 0 : 1;
    }

    /**
     * Reports what to add and what to withdraw to get from one set to another.
     *
     * <p>Withdrawals come back first so a caller applies them first. A prefix that moved from one
     * kind to the other has to lose its old entry before the new one goes in, or the platform
     * would either refuse the duplicate or silently keep whichever it saw first.
     */
    public static Difference diff(List<Route> current, List<Route> desired) {
        Map<String, Route> desiredByCidr = new LinkedHashMap<>();
        for (Route route : desired) {
            desiredByCidr.put(route.cidr(), route);
        }
        Map<String, Route> currentByCidr = new LinkedHashMap<>();
        for (Route route : current) {
            currentByCidr.put(route.cidr(), route);
        }

        List<Route> remove = new ArrayList<>();
        for (Route route : current) {
            Route want = desiredByCidr.get(route.cidr());
            if (want == null || want.kind() != route.kind()) {
                remove.add(route);
            }
        }
        List<Route> add = new ArrayList<>();
        for (Route route : desired) {
            Route have = currentByCidr.get(route.cidr());
            if (have == null || have.kind() != route.kind()) {
                add.add(route);
            }
        }
        sort(remove);
        sort(add);
        return new Difference(remove, add);
    }
}
