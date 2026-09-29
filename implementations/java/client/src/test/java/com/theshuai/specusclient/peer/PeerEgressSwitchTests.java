package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import com.theshuai.specusclient.cli.EgressView;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The consumer's master switch, {@code peerEgressEnabled}, off: the rules are kept, none is in
 * force, and each says why. Bound to the {@code consumerDisabled} section of the shared rules vector,
 * which the Go and .NET clients read too.
 */
class PeerEgressSwitchTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve("peer-egress-rules-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-rules-v1.json");
    }

    private static List<PeerEgressRule> rules(JsonNode vector) throws IOException {
        List<PeerEgressRule> rules = new ArrayList<>();
        for (JsonNode node : vector.path("rules")) {
            rules.add(MAPPER.treeToValue(node, PeerEgressRule.class));
        }
        return rules;
    }

    @Test
    void everyRuleIsOutOfForceAndSaysWhyWithTheSwitchOff() throws IOException {
        JsonNode vector = vector();
        List<PeerEgressRule> rules = rules(vector);
        JsonNode section = vector.path("consumerDisabled");
        assertEquals(rules.size(), section.path("ruleCodes").size(), "the vector names every rule");

        List<Map<String, Object>> listed = PeerEgressStatus.switchedOffRules(rules);
        for (JsonNode want : section.path("ruleCodes")) {
            Map<String, Object> entry = listed.get(want.path("index").asInt());
            assertEquals(false, entry.get("inForce"), "rule " + want.path("index").asInt());
            assertEquals(want.path("code").asText(), entry.get("code"), "rule " + want.path("index").asInt());
        }
        // Off, the reconcile hands the engine no rules at all; nothing it is asked about matches.
        for (JsonNode testCase : section.path("cases")) {
            var decision = PeerEgressRules.match(List.of(), testCase.path("destination").asText(),
                    vector.path("meshCidr").asText());
            assertEquals(testCase.path("expect").path("action").asText(), decision.action());
            assertFalse(decision.matched(), testCase.path("destination").asText());
        }
    }

    @Test
    void theStatusSectionKeepsTheRulesAndTheCommandSaysTakeoverIsOff() throws IOException {
        List<PeerEgressRule> rules = rules(vector());
        Map<String, Object> status = PeerEgressStatus.section(null, List.of(),
                PeerEgressStatus.ApplyOutcome.none(), null, false, rules);
        @SuppressWarnings("unchecked")
        Map<String, Object> consumer = (Map<String, Object>) status.get("consumer");
        assertEquals(false, consumer.get("enabled"));
        assertEquals(false, consumer.get("active"));
        assertEquals(rules.size(), ((List<?>) consumer.get("rules")).size());

        List<String> lines = EgressView.lines(MAPPER.valueToTree(status));
        assertTrue(lines.get(0).equals("  consumer: takeover off | " + rules.size()
                + " rules saved, none in force (peerEgressEnabled is false)"), lines.get(0));
    }
}
