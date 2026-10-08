package com.theshuai.common.peeregress;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Binds the IPv6 spelling and IPv6 rules to the {@code ipv6Prefixes} and {@code ipv6} sections of
 * {@code protocol/test-vectors/peer-egress-rules-v1.json}, the sections the Go and .NET
 * implementations read.
 */
class PeerEgressIpv6VectorTests {
    @Test
    void spellingMatchesSharedVector() throws IOException {
        JsonNode prefixes = readVector().path("ipv6Prefixes");
        assertFalse(prefixes.path("accept").isEmpty(), "rules vector carried no ipv6Prefixes");
        for (JsonNode node : prefixes.path("accept")) {
            String text = node.path("text").asText();
            String address = node.path("address").asText();
            int length = node.path("prefixLength").asInt();
            Ipv6Cidr.Parsed parsed = Ipv6Cidr.parseWithLength(text);
            assertNotNull(parsed, text);
            assertEquals(address, Ipv6Cidr.formatAddress(parsed.cidr().high(), parsed.cidr().low()), text);
            assertEquals(length, parsed.cidr().prefixLength(), text);
            // The canonical form reads back as the same address.
            assertArrayEquals(new long[] {parsed.cidr().high(), parsed.cidr().low()}, Ipv6Cidr.parseAddress(address), text);
            // What a server stores: the canonical address, with the length only when it was written.
            assertEquals(parsed.hadLength() ? address + "/" + length : address, Ipv6Cidr.storedDestinationCidr(text), text);
        }
        assertFalse(prefixes.path("reject").isEmpty(), "rules vector carried no refused IPv6 spellings");
        for (JsonNode node : prefixes.path("reject")) {
            String text = node.path("text").asText();
            assertNull(Ipv6Cidr.parse(text), text);
            assertNull(Ipv6Cidr.storedDestinationCidr(text), text);
        }
    }

    @Test
    void rulesMatchSharedVectorWithAnIpv6DataPlane() throws IOException {
        JsonNode section = readVector().path("ipv6");
        List<PeerEgressRule> rules = rules(section);
        Map<Integer, String> refused = new HashMap<>();
        for (JsonNode node : section.path("refusedRules")) {
            refused.put(node.path("index").asInt(), node.path("code").asText());
        }
        for (int index = 0; index < rules.size(); index++) {
            assertEquals(refused.get(index), PeerEgressRules.validate(rules.get(index),
                    PeerEgressRules.DEFAULT_MESH_CIDR, null, true), "ipv6 rule " + index);
        }
        for (JsonNode node : section.path("cases")) {
            assertMatch(node, PeerEgressRules.match(rules, node.path("destination").asText(),
                    PeerEgressRules.DEFAULT_MESH_CIDR, null, true));
        }
        for (JsonNode node : section.path("configValidation")) {
            PeerEgressRule rule = JsonUtil.stringToObject(node.path("rule").toString(), PeerEgressRule.class);
            String want = node.path("code").isNull() ? null : node.path("code").asText();
            assertEquals(want, PeerEgressRules.validate(rule, PeerEgressRules.DEFAULT_MESH_CIDR, null, true),
                    node.path("name").asText());
        }
    }

    /**
     * What every client does today: the same list with no IPv6 data plane, through the production
     * entry points, so turning {@link PeerEgressRules#CONSUMER_CARRIES_IPV6} on without the data plane
     * fails here.
     */
    @Test
    void ipv6RulesAreNotInForceWithoutAnIpv6DataPlane() throws IOException {
        JsonNode section = readVector().path("ipv6");
        List<PeerEgressRule> rules = rules(section);
        JsonNode without = section.path("withoutIpv6DataPlane");
        for (JsonNode node : without.path("ruleCodes")) {
            String want = node.path("code").isNull() ? null : node.path("code").asText();
            assertEquals(want, PeerEgressRules.validate(rules.get(node.path("index").asInt()),
                    PeerEgressRules.DEFAULT_MESH_CIDR), "ipv6 rule " + node.path("index").asInt());
        }
        for (JsonNode node : without.path("cases")) {
            assertMatch(node, PeerEgressRules.match(rules, node.path("destination").asText(),
                    PeerEgressRules.DEFAULT_MESH_CIDR));
        }
    }

    private static List<PeerEgressRule> rules(JsonNode section) throws IOException {
        List<PeerEgressRule> rules = new ArrayList<>();
        for (JsonNode node : section.path("rules")) {
            assertEquals(rules.size(), node.path("index").asInt(), "ipv6 rule index");
            rules.add(JsonUtil.stringToObject(node.toString(), PeerEgressRule.class));
        }
        assertFalse(rules.isEmpty(), "rules vector carried no ipv6 rules");
        return rules;
    }

    private static void assertMatch(JsonNode node, PeerEgressRules.Match match) {
        String name = node.path("destination").asText();
        JsonNode expect = node.path("expect");
        assertEquals(expect.path("action").asText(), match.action(), name);
        if (expect.path("matchedRuleIndex").isNull()) {
            assertNull(match.matchedRuleIndex(), name);
        } else {
            assertEquals(expect.path("matchedRuleIndex").asInt(), match.matchedRuleIndex(), name);
        }
        if (expect.has("egressClientId")) {
            assertEquals(expect.path("egressClientId").asLong(), match.egressClientId(), name);
        }
    }

    private static JsonNode readVector() throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/peer-egress-rules-v1.json");
            if (Files.isRegularFile(candidate)) {
                return JsonUtil.readString(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate peer-egress-rules-v1.json");
    }
}
