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
        var rules = effective.getPeerEgressRules();
        if (rules == null) return;
        for (int index = 0; index < rules.size(); index++) {
            String code = com.theshuai.common.peeregress.PeerEgressRules.validate(rules.get(index),
                    com.theshuai.common.peeregress.PeerEgressRules.DEFAULT_MESH_CIDR);
            if (code != null) warning.accept("peerEgressRules[" + index + "] is not in force: " + code);
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
