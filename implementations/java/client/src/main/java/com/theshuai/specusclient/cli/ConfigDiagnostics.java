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
