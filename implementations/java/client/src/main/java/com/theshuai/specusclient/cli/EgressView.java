package com.theshuai.specusclient.cli;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Rendering the egress section of a live instance's state for a person.
 *
 * <p>The JSON form carries everything; this decides what a person is shown. The rule it follows is
 * to print the problems and count the rest: a rule that is configured but not in force, a route
 * this feature wanted and did not get, an egress peer a rule names that is offline. Those are the
 * three ways the feature can be doing nothing while every other surface looks healthy, and they are
 * the reason the section exists.
 *
 * <p>So a working node prints two lines and a broken one prints those two plus exactly what is
 * wrong. Listing the healthy rules too would push the one line that matters off the screen on any
 * node with a real rule set.
 *
 * <p>Every read here tolerates a missing or wrongly typed field rather than asserting one, because
 * the state file may have been written by the Go or .NET client. A status command that failed on a
 * field somebody spelled differently would be worse than one that prints a zero. Jackson's
 * {@code path} does that by returning a missing node, which is why it is used throughout.
 */
public final class EgressView {

    private EgressView() {
    }

    public static List<String> lines(JsonNode section) {
        if (section == null || section.isMissingNode() || section.isNull()) {
            return List.of("  No egress state. This build reported none.");
        }
        List<String> lines = new ArrayList<>(consumerLines(section.path("consumer")));
        lines.addAll(egressLines(section.path("egress")));
        return lines;
    }

    private static List<String> consumerLines(JsonNode consumer) {
        if (!consumer.path("active").asBoolean(false)) {
            return List.of("  consumer: not configured (no rules have been applied)");
        }
        List<JsonNode> rules = list(consumer.path("rules"));
        List<JsonNode> routes = list(consumer.path("routes"));
        List<JsonNode> peers = list(consumer.path("peers"));
        long refused = rules.stream().filter(rule -> !rule.path("inForce").asBoolean(false)).count();
        long notInstalled =
                routes.stream().filter(route -> !route.path("installed").asBoolean(false)).count();
        long offline = peers.stream().filter(peer -> !peer.path("online").asBoolean(false)).count();

        List<String> lines = new ArrayList<>();
        lines.add(String.format(
                "  consumer: %d rules (%d not in force) | %d routes (%d not installed) | %d flows"
                        + " | %d egress peers (%d offline)",
                rules.size(), refused, routes.size(), notInstalled,
                consumer.path("flows").asLong(0), peers.size(), offline));

        // Then the problems, one line each, in the order an operator would act on them: a rule
        // that is not in force steers nothing at all, a route that is not installed means the
        // traffic leaves locally, and an offline peer means the rule is in force with nowhere to
        // send.
        for (JsonNode rule : rules) {
            if (rule.path("inForce").asBoolean(false)) {
                continue;
            }
            lines.add(String.format("    rule %d \"%s\": NOT IN FORCE (%s)",
                    rule.path("index").asLong(0), rule.path("match").asText(""),
                    rule.path("code").asText("")));
        }
        for (JsonNode route : routes) {
            if (route.path("installed").asBoolean(false)) {
                continue;
            }
            lines.add(String.format("    route %s (%s): NOT INSTALLED, already present: %s",
                    route.path("cidr").asText(""), route.path("origin").asText(""),
                    route.path("conflict").asText("")));
        }
        for (JsonNode peer : peers) {
            if (peer.path("online").asBoolean(false)) {
                continue;
            }
            lines.add(String.format(
                    "    egress peer %d: offline, so its rules have nowhere to send",
                    peer.path("clientId").asLong(0)));
        }
        String error = consumer.path("routeError").asText("");
        if (!error.isEmpty()) {
            lines.add(String.format("    route install failed: %s (rolledBack=%s)", error,
                    consumer.path("rolledBack").asBoolean(false)));
        }
        Map<String, Long> blocked = counts(consumer.path("blocked"));
        if (!blocked.isEmpty()) {
            lines.add("    blocked: " + join(blocked));
        }
        return lines;
    }

    private static List<String> egressLines(JsonNode egress) {
        if (!egress.path("active").asBoolean(false)) {
            // Not a problem and not hidden either. A node that is only a consumer says so, which
            // is what tells an operator who expected it to serve that no policy has arrived.
            return List.of("  egress: not serving (no policy has enabled it)");
        }
        List<String> lines = new ArrayList<>();
        lines.add(String.format("  egress: serving | %d flows | %d total | in %d B | out %d B",
                egress.path("flows").asLong(0), egress.path("totalFlows").asLong(0),
                egress.path("bytesIn").asLong(0), egress.path("bytesOut").asLong(0)));
        Map<String, Long> refused = counts(egress.path("refused"));
        if (!refused.isEmpty()) {
            // By code, because each code is a different conversation to have with whoever owns the
            // other end.
            lines.add("    refused: " + join(refused));
        }
        return lines;
    }

    private static List<JsonNode> list(JsonNode node) {
        List<JsonNode> entries = new ArrayList<>();
        if (node.isArray()) {
            for (JsonNode entry : node) {
                if (entry.isObject()) {
                    entries.add(entry);
                }
            }
        }
        return entries;
    }

    private static Map<String, Long> counts(JsonNode node) {
        Map<String, Long> counts = new TreeMap<>();
        if (!node.isObject()) {
            return counts;
        }
        node.fields().forEachRemaining(field -> {
            // Zeros are dropped rather than printed. A counter that has never fired says nothing,
            // and a line of them would bury the one that has.
            long count = field.getValue().asLong(0);
            if (count != 0) {
                counts.put(field.getKey(), count);
            }
        });
        return counts;
    }

    private static String join(Map<String, Long> counts) {
        StringBuilder text = new StringBuilder();
        counts.forEach((name, count) -> {
            if (text.length() > 0) {
                text.append(", ");
            }
            text.append(name).append('=').append(count);
        });
        return text.toString();
    }
}
