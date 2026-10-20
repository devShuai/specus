package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.Ipv6Cidr;
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
        return plan(rules, bypass, meshCidr, null);
    }

    /** The origin of the route that captures the fake-IP pool while phase two runs. */
    public static final String ORIGIN_FAKE_IP_POOL = "fake-ip-pool";

    /**
     * As above while phase two runs with the given pool (null when it does not).
     *
     * <p>The pool is one more prefix sent into the TUN, with origin {@link #ORIGIN_FAKE_IP_POOL}:
     * an address handed out for a name must reach the consumer to be sent by that name, and one
     * handed out for nothing must reach it to be refused. It is planned, journalled, checked for
     * conflicts and rolled back exactly as a rule's route is, and it counts as capturing for the
     * bypass, so an endpoint that happens to sit in the pool is still pinned outside the tunnel.
     * Domain rules install nothing themselves; the pool route is what carries their traffic.
     */
    public static Plan plan(List<PeerEgressRule> rules, List<String> bypass, String meshCidr, String fakeIpCidr) {
        return plan(rules, bypass, meshCidr, fakeIpCidr, false);
    }

    /**
     * As above, with the consumer's IPv6 data plane stated.
     *
     * <p>The two families are planned apart and by the same rules ({@code protocol/spec/peer-egress.md},
     * IPv6 数据面, 消费端): exact IPv6 prefixes, nothing invented -- no {@code ::/0} and no {@code ::/1}
     * plus {@code 8000::/1} -- nothing for a direct rule, a route for a block rule, and a /128 bypass
     * for each IPv6 endpoint an IPv6 rule's prefix covers. A prefix of one family never covers an
     * address of the other, so neither family's plan changes the other's. Without the data plane no
     * IPv6 rule is in force, and the plan is exactly what it was before IPv6 existed.
     */
    public static Plan plan(List<PeerEgressRule> rules, List<String> bypass, String meshCidr, String fakeIpCidr,
            boolean carriesIpv6) {
        List<PeerEgressRule> ruleList = rules == null ? List.of() : rules;
        List<Refusal> refused = new ArrayList<>();
        Set<Integer> skip = new LinkedHashSet<>();
        for (int index = 0; index < ruleList.size(); index++) {
            PeerEgressRule rule = ruleList.get(index);
            String code = PeerEgressRules.validate(rule, meshCidr, fakeIpCidr, carriesIpv6);
            if (code != null) {
                refused.add(new Refusal(index, rule == null ? "" : rule.getMatch(), code));
                skip.add(index);
            }
        }

        // The prefixes the rules want captured come first, because they decide which bypass
        // addresses need a route at all.
        //
        // A direct rule installs nothing. Traffic stays local by not having a route, which is the
        // same mechanism that makes unmatched traffic local, so there is one behaviour rather than
        // two that have to agree. A block rule does install one: the packet has to be captured
        // before it can be dropped, and the data plane is what drops it.
        record Captured(Ipv4Cidr cidr, String origin) {
        }
        record Captured6(Ipv6Cidr cidr, String origin) {
        }
        Set<String> seen = new LinkedHashSet<>();
        List<Captured> capturing = new ArrayList<>();
        List<Captured6> capturing6 = new ArrayList<>();
        for (int index = 0; index < ruleList.size(); index++) {
            if (skip.contains(index)) {
                continue;
            }
            PeerEgressRule rule = ruleList.get(index);
            String action = rule.getAction() == null ? "" : rule.getAction().trim();
            if (!PeerEgressRule.ACTION_EGRESS.equals(action) && !PeerEgressRule.ACTION_BLOCK.equals(action)) {
                continue;
            }
            if (PeerEgressRules.isIpv6(rule)) {
                // In force only with the data plane, so validation has already let it through or not.
                Ipv6Cidr cidr6 = Ipv6Cidr.parse(rule.getMatch().trim());
                if (cidr6 != null && seen.add(cidr6.toString())) {
                    capturing6.add(new Captured6(cidr6, "rule:" + rule.getMatch()));
                }
                continue;
            }
            Ipv4Cidr cidr = Ipv4Cidr.parse(rule.getMatch());
            if (cidr == null) {
                continue;
            }
            // Rendered the one way this feature writes a prefix, so a route installed in one run
            // is recognised as the same route in the next.
            if (!seen.add(cidr.toString())) {
                // Two rules over the same prefix need one route; the engine decides between them
                // per packet, and installing the prefix twice would make removal ambiguous.
                continue;
            }
            capturing.add(new Captured(cidr, "rule:" + rule.getMatch()));
        }
        Ipv4Cidr pool = fakeIpCidr == null ? null : Ipv4Cidr.parse(fakeIpCidr);
        // No rule shares its prefix: validation refuses every address rule reaching into it.
        if (pool != null && seen.add(pool.toString())) {
            capturing.add(new Captured(pool, ORIGIN_FAKE_IP_POOL));
        }

        seen = new LinkedHashSet<>();
        List<Route> routes = new ArrayList<>();

        // A bypass address gets a /32 only when one of those prefixes covers it. Uncovered, the
        // platform's own routing already carries it, and a route of ours would be one more thing
        // to keep true as peers come and go. Covered, the /32 is what keeps the tunnel's transport
        // out of the tunnel, and it goes in first so a rule naming the same prefix cannot displace
        // it.
        for (String endpoint : bypass == null ? List.<String>of() : bypass) {
            Integer address = Ipv4Cidr.parseAddress(endpoint == null ? null : endpoint.trim());
            if (address == null) {
                // An IPv6 endpoint gets its /128 the same way, when an IPv6 rule covers it.
                long[] address6 = Ipv6Cidr.parseAddress(endpoint == null ? null : endpoint.trim());
                if (address6 == null) {
                    continue;
                }
                boolean covered6 = false;
                for (Captured6 entry : capturing6) {
                    if (entry.cidr().contains(address6)) {
                        covered6 = true;
                        break;
                    }
                }
                String cidr = Ipv6Cidr.formatAddress(address6[0], address6[1]) + "/128";
                if (covered6 && seen.add(cidr)) {
                    routes.add(new Route(cidr, Kind.BYPASS, "bypass"));
                }
                continue;
            }
            boolean covered = false;
            for (Captured entry : capturing) {
                if (entry.cidr().contains(address)) {
                    covered = true;
                    break;
                }
            }
            if (!covered) {
                continue;
            }
            String cidr = Ipv4Cidr.format(address) + "/32";
            if (seen.add(cidr)) {
                routes.add(new Route(cidr, Kind.BYPASS, "bypass"));
            }
        }

        for (Captured entry : capturing) {
            String normalised = entry.cidr().toString();
            if (seen.add(normalised)) {
                routes.add(new Route(normalised, Kind.TUN, entry.origin()));
            }
        }
        for (Captured6 entry : capturing6) {
            // Written the one way this feature writes an IPv6 prefix, RFC 5952 and the length, so a
            // route installed in one run is recognised as the same route in the next.
            String normalised = entry.cidr().toString();
            if (seen.add(normalised)) {
                routes.add(new Route(normalised, Kind.TUN, entry.origin()));
            }
        }

        sort(routes);
        return new Plan(routes, refused);
    }

    /**
     * How long an apply that left something undone -- a conflict or a failure -- waits before the
     * same plan is tried again. Long enough that an operator's route sitting on one of our
     * prefixes is not queried every tick, short enough that its removal is noticed.
     *
     * <p>Shared vector: {@code reconcile.retryAfterMs}.
     */
    public static final long RETRY_AFTER_MILLIS = 60_000L;

    /**
     * What the last apply was asked to install, and how it went.
     *
     * @param troubled the apply left something undone: a prefix refused because somebody else
     *                 owned it, or an install that failed and was rolled back
     */
    public record PlanAttempt(long atMillis, List<Route> desired, boolean troubled) {
    }

    /**
     * Whether a plan computed on the periodic tick should be applied.
     *
     * <p>The plan is recomputed every few seconds because its inputs move: peers come and go, the
     * relay changes, a hostname resolves differently. Applying every time would rewrite the journal
     * on every tick for nothing. So a plan is applied when it differs from the one last applied,
     * and otherwise only to retry an apply that left something undone, and then no more often than
     * the interval.
     *
     * <p>Compared as sets: the planner sorts, but nothing here should depend on that.
     */
    public static boolean reconcileDue(PlanAttempt last, List<Route> desired, long nowMillis) {
        if (last == null) {
            return true;
        }
        List<Route> previous = new ArrayList<>(last.desired());
        List<Route> next = new ArrayList<>(desired);
        sort(previous);
        sort(next);
        if (!previous.equals(next)) {
            return true;
        }
        return last.troubled() && nowMillis - last.atMillis() >= RETRY_AFTER_MILLIS;
    }

    /**
     * Orders bypass entries first, then IPv4 before IPv6, then by prefix.
     *
     * <p>Bypass first because installation happens in this order: the addresses that keep the
     * tunnel's own transport working are in place before anything is pointed into the tunnel.
     * Deterministic order also means the journal and every log line read the same way run to run.
     * The family comes before the prefix so the order stays one order when both are present:
     * compared as text across families and as numbers within one, three prefixes could each sort
     * before the next.
     */
    public static void sort(List<Route> routes) {
        routes.sort(PeerEgressRoutePlanner::compare);
    }

    private static int compare(Route left, Route right) {
        int order = Integer.compare(rank(left.kind()), rank(right.kind()));
        if (order != 0) {
            return order;
        }
        boolean left6 = isIpv6(left);
        boolean right6 = isIpv6(right);
        if (left6 != right6) {
            return left6 ? 1 : -1;
        }
        if (left6) {
            Ipv6Cidr leftCidr6 = Ipv6Cidr.parse(left.cidr());
            Ipv6Cidr rightCidr6 = Ipv6Cidr.parse(right.cidr());
            if (leftCidr6 == null || rightCidr6 == null) {
                return left.cidr().compareTo(right.cidr());
            }
            order = Long.compareUnsigned(leftCidr6.high(), rightCidr6.high());
            if (order == 0) {
                order = Long.compareUnsigned(leftCidr6.low(), rightCidr6.low());
            }
            return order != 0 ? order : Integer.compare(leftCidr6.prefixLength(), rightCidr6.prefixLength());
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

    /** Whether a route's prefix is IPv6, which a colon settles. */
    public static boolean isIpv6(Route route) {
        return route.cidr().indexOf(':') >= 0;
    }

    /** The address a bypass route pins: its prefix without the /32 or /128. */
    public static String bypassAddress(String cidr) {
        String suffix = cidr.indexOf(':') >= 0 ? "/128" : "/32";
        return cidr.endsWith(suffix) ? cidr.substring(0, cidr.length() - suffix.length()) : cidr;
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
