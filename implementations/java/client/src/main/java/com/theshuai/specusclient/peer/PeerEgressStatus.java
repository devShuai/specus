package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * What an operator can read about this node's egress roles.
 *
 * <p>Until this existed the feature could not say what it was doing. A rule an operator wrote and
 * this feature refused was written to the log once, at the moment it was refused, and then nowhere:
 * the route planner's own comment calls that "a leak they have no way to notice". Same for a route
 * that was not installed because something else already owned the prefix -- the traffic goes out
 * locally and every surface looks healthy.
 *
 * <p>Two of the fields here are derived rather than remembered, and that is deliberate. Whether a
 * rule is in force is recomputed from the rule itself, the same way
 * {@link PeerEgressRules#match} recomputes it before every decision, so the status cannot drift
 * from what steering actually does. Whether a route is installed cannot be derived -- the answer
 * came from the platform's routing table at apply time -- so that one is remembered.
 *
 * <p>Nothing secret travels here. Rule matches and prefixes are the operator's own configuration
 * and client IDs already appear in the peer list; tokens, keys and addresses learned from other
 * peers do not.
 *
 * <p>The shape is the one {@code protocol/spec/peer-egress.md} pins, because the Go and .NET
 * clients write the same state file and any of the three CLIs reads whichever wrote it.
 */
public final class PeerEgressStatus {

    private PeerEgressStatus() {
    }

    /**
     * What the last route apply left behind that cannot be recomputed.
     *
     * <p>Only the conflicts, because only they came from outside: the installed set is in the
     * journal, and which rules are in force is recomputed from the rules.
     */
    public record ApplyOutcome(long atMillis, List<PeerEgressRouteInstaller.RouteConflict> conflicts,
            String error, boolean rolledBack, boolean applied) {

        /** Nothing has been applied yet, which has to read differently from "applied nothing". */
        public static ApplyOutcome none() {
            return new ApplyOutcome(0L, List.of(), "", false, false);
        }
    }

    /** The consumer's own view, taken under its lock. */
    public record ConsumerSnapshot(List<PeerEgressRule> rules, String meshCidr,
            Map<Long, Boolean> online, int flows, Map<String, Long> blocked) {
    }

    /** The egress role's own view, taken under its lock. */
    public record RuntimeSnapshot(boolean enabled, long revision, int flows,
            PeerEgressRuntime.Stats stats, Map<String, Long> refused) {
    }

    /** The whole section, assembled for the state file. */
    public static Map<String, Object> section(ConsumerSnapshot consumer,
            List<PeerEgressRoutePlanner.Route> installed, ApplyOutcome outcome,
            RuntimeSnapshot runtime) {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("consumer", consumerSection(consumer, installed, outcome));
        status.put("egress", egressSection(runtime));
        return status;
    }

    private static Map<String, Object> consumerSection(ConsumerSnapshot consumer,
            List<PeerEgressRoutePlanner.Route> installed, ApplyOutcome outcome) {
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("active", consumer != null);
        section.put("rules", List.of());
        section.put("routes", List.of());
        section.put("peers", List.of());
        section.put("flows", 0);
        // Counted by reason rather than totalled: "no egress online" and "denied by the egress"
        // are the same number and completely different problems.
        section.put("blocked", Map.of());
        if (consumer == null) {
            return section;
        }

        List<Map<String, Object>> rules = new ArrayList<>();
        Map<Long, Boolean> peers = new TreeMap<>();
        for (int index = 0; index < consumer.rules().size(); index++) {
            PeerEgressRule rule = consumer.rules().get(index);
            // validate returns null for a usable rule here, where the Go implementation returns an
            // empty string. Normalised at the boundary rather than compared against null twice
            // below: "in force" is one condition, and writing it two ways is how the two halves of
            // this section end up disagreeing about the same rule.
            String refusal = PeerEgressRules.validate(rule, consumer.meshCidr());
            String code = refusal == null ? "" : refusal;
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("index", index);
            entry.put("match", rule.getMatch() == null ? "" : rule.getMatch().trim());
            entry.put("action", rule.getAction() == null ? "" : rule.getAction().trim());
            // inForce is the field worth having. A rule that is configured but refused reads
            // false and carries its code, which is the difference between "this rule is
            // protecting me" and "this rule is text in a file".
            entry.put("inForce", code.isEmpty());
            if (!code.isEmpty()) {
                entry.put("code", code);
            }
            Long target = rule.getEgressClientId();
            if (target != null && target != 0L) {
                entry.put("egressClientId", target);
                if (code.isEmpty()) {
                    // Only rules that steer contribute a peer. A refused rule naming a peer
                    // would otherwise report an egress this node will never send to.
                    peers.put(target, Boolean.TRUE.equals(consumer.online().get(target)));
                }
            }
            if (rule.getPort() != null && rule.getPort() != 0) {
                entry.put("port", rule.getPort());
            }
            rules.add(entry);
        }
        section.put("rules", rules);

        List<Map<String, Object>> peerEntries = new ArrayList<>();
        for (Map.Entry<Long, Boolean> peer : peers.entrySet()) {
            peerEntries.add(Map.of("clientId", peer.getKey(), "online", peer.getValue()));
        }
        section.put("peers", peerEntries);
        section.put("flows", consumer.flows());
        section.put("blocked", new TreeMap<>(consumer.blocked()));
        section.put("routes", routesSection(installed, outcome));
        if (outcome.applied()) {
            section.put("appliedAtUnixMs", outcome.atMillis());
            section.put("rolledBack", outcome.rolledBack());
            if (!outcome.error().isEmpty()) {
                section.put("routeError", outcome.error());
            }
        }
        return section;
    }

    /**
     * The routes this feature owns and the ones it wanted and did not get.
     *
     * <p>The installed set comes from the journal rather than from the last apply, because the
     * journal is what a restart adopts: after a crash the routes are still in the table and the
     * apply that put them there belongs to a process that is gone.
     */
    private static List<Map<String, Object>> routesSection(
            List<PeerEgressRoutePlanner.Route> installed, ApplyOutcome outcome) {
        List<Map<String, Object>> routes = new ArrayList<>();
        for (PeerEgressRoutePlanner.Route route : installed) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("cidr", route.cidr());
            entry.put("kind", route.kind().wireName());
            entry.put("origin", route.origin());
            entry.put("installed", true);
            routes.add(entry);
        }
        // A route refused because the prefix already had an owner is still listed, with installed
        // false and what owns it. Dropping it would make the status look clean while the traffic it
        // was meant to capture leaves by the physical interface.
        for (PeerEgressRouteInstaller.RouteConflict conflict : outcome.conflicts()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("cidr", conflict.route().cidr());
            entry.put("kind", conflict.route().kind().wireName());
            entry.put("origin", conflict.route().origin());
            entry.put("installed", false);
            entry.put("conflict", conflict.existing());
            routes.add(entry);
        }
        routes.sort(Comparator
                .comparing((Map<String, Object> entry) -> String.valueOf(entry.get("cidr")))
                .thenComparing(entry -> String.valueOf(entry.get("origin"))));
        return routes;
    }

    private static Map<String, Object> egressSection(RuntimeSnapshot runtime) {
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("active", false);
        section.put("flows", 0);
        section.put("refused", Map.of());
        if (runtime == null) {
            return section;
        }
        section.put("active", runtime.enabled());
        section.put("flows", runtime.flows());
        section.put("refused", new TreeMap<>(runtime.refused()));
        section.put("totalFlows", runtime.stats().totalFlows());
        section.put("bytesIn", runtime.stats().bytesIn());
        section.put("bytesOut", runtime.stats().bytesOut());
        if (runtime.revision() != 0L) {
            section.put("revision", runtime.revision());
        }
        return section;
    }
}
