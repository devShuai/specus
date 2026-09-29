package com.theshuai.specusclient.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import java.util.function.Consumer;

final class ConfigDiagnostics {
    private ConfigDiagnostics() { }

    static void report(JsonNode raw, JsonNode shape, ClientStartupConfig effective, Consumer<String> warning) {
        unknown(raw, shape, "", warning);
        normalized(raw, "peerMeshMtu", effective.getPeerMeshMtu(), warning);
        normalized(raw, "updateCheckIntervalHours", effective.getUpdateCheckIntervalHours(), warning);
        if (effective.isAutoUpdate()) warning.accept("autoUpdate is accepted for shared configuration; Java only notifies and never installs updates automatically");
        egressRules(effective, warning);
    }

    /**
     * Names every egress rule that will not be in force, before anything connects.
     *
     * <p>A warning rather than a failure, matching the runtime: a refused rule is skipped and the
     * rest take effect. The index and the code are printed and the match is not, since
     * configuration warnings do not print configuration values. Checked against the default mesh
     * network, because the real one arrives from the server at login.
     */
    private static void egressRules(ClientStartupConfig effective, Consumer<String> warning) {
        // Phase two asked for over a pool it cannot use stops phase two alone, so it is said here
        // too: otherwise the domain rules below read as unsupported with nothing naming the pool.
        if (effective.isPeerEgressDnsTakeover()) {
            String problem = com.theshuai.common.peeregress.PeerEgressDns.poolProblem(
                    effective.getPeerEgressFakeIpCidr(), com.theshuai.common.peeregress.PeerEgressRules.DEFAULT_MESH_CIDR);
            if (problem != null)
                warning.accept("peerEgressFakeIpCidr is not usable: " + problem + "; domain rules are not in force");
        }
        var rules = effective.getPeerEgressRules();
        if (rules == null) return;
        // Kept with the master switch off is the one state where nothing is in force by design,
        // said once rather than left to be discovered. A rule the user switched off is not warned
        // about: it is out of force because they asked.
        if (!rules.isEmpty() && !effective.isPeerEgressEnabled())
            warning.accept("peerEgressRules has " + rules.size()
                    + " rule(s) but peerEgressEnabled is false: none is in force");
        // Judged against the pool phase two would run with, so a domain rule is not reported as
        // unsupported while takeover is asked for, and an address rule in the pool is.
        String pool = com.theshuai.common.peeregress.PeerEgressDns.configuredPool(
                effective.isPeerEgressDnsTakeover(), effective.getPeerEgressFakeIpCidr());
        for (int index = 0; index < rules.size(); index++) {
            String code = com.theshuai.common.peeregress.PeerEgressRules.validate(rules.get(index),
                    com.theshuai.common.peeregress.PeerEgressRules.DEFAULT_MESH_CIDR, pool);
            if (code != null && !com.theshuai.common.peeregress.PeerEgressCodes.RULE_DISABLED.equals(code))
                warning.accept("peerEgressRules[" + index + "] is not in force: " + code);
        }
    }

    private static void normalized(JsonNode raw, String field, long value, Consumer<String> warning) {
        if (raw.has(field) && (!raw.get(field).isIntegralNumber() || raw.get(field).longValue() != value))
            warning.accept(field + " normalized to " + value);
    }

    private static void unknown(JsonNode raw, JsonNode shape, String prefix, Consumer<String> warning) {
        raw.fields().forEachRemaining(entry -> {
            String key = entry.getKey();
            if (!shape.has(key)) warning.accept("Unknown configuration field " + TextNode.valueOf(prefix + key) + "; ignored");
            else if (entry.getValue().isObject() && shape.get(key).isObject())
                unknown(entry.getValue(), shape.get(key), prefix + key + ".", warning);
        });
    }
}
