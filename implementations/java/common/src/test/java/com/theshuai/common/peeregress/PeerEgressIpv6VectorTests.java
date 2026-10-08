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

    /**
     * Egress-side authorization of IPv6 destinations against the {@code ipv6} section of
     * {@code peer-egress-authz-v1.json}.
     */
    @Test
    void authorizationOfIpv6DestinationsMatchesSharedVector() throws IOException {
        JsonNode section = readVector("peer-egress-authz-v1.json").path("ipv6");
        assertEquals(strings(section.path("forcedDenyCidrs")), PeerEgressAuthorization.FORCED_DENY_CIDRS6);
        assertEquals(strings(section.path("cloudMetadataCidrs")), PeerEgressAuthorization.CLOUD_METADATA_CIDRS6);
        assertEquals(strings(section.path("lanCidrs")), PeerEgressAuthorization.LAN_CIDRS6);
        List<JsonNode> cases = new ArrayList<>();
        section.path("cases").forEach(cases::add);
        section.path("policyVariantCases").forEach(cases::add);
        assertFalse(cases.isEmpty(), "authorization vector carried no IPv6 cases");
        PeerEgressAuthorization.Context context = PeerEgressAuthorization.Context.defaults();
        for (JsonNode node : cases) {
            PeerEgressPolicy policy = JsonUtil.stringToObject(section.path("policy").toString(), PeerEgressPolicy.class);
            JsonNode overrides = node.path("policyOverride");
            if (!overrides.isMissingNode()) {
                PeerEgressPolicy override = JsonUtil.stringToObject(overrides.toString(), PeerEgressPolicy.class);
                policy.setScope(override.getScope());
                policy.setDestinationRules(override.getDestinationRules());
            }
            PeerEgressRequest request = JsonUtil.stringToObject(node.path("request").toString(), PeerEgressRequest.class);
            PeerEgressAuthorization.Decision decision = PeerEgressAuthorization.evaluate(request, policy, true, context);
            assertEquals(node.path("expect").path("code").asText(), decision.code(), node.path("name").asText());
            assertEquals(node.path("expect").path("allowed").asBoolean(), decision.allowed(), node.path("name").asText());
        }
        // Every forced-deny entry holds against the broad ::/0 rule in the vector's policy.
        PeerEgressPolicy policy = JsonUtil.stringToObject(section.path("policy").toString(), PeerEgressPolicy.class);
        List<String> denied = new ArrayList<>(strings(section.path("forcedDenyCidrs")));
        denied.addAll(strings(section.path("cloudMetadataCidrs")));
        for (String text : denied) {
            Ipv6Cidr cidr = Ipv6Cidr.parse(text);
            assertNotNull(cidr, text);
            PeerEgressRequest request = new PeerEgressRequest();
            request.setConsumerClientId(1L);
            request.setDestinationIp(Ipv6Cidr.formatAddress(cidr.high(), cidr.low()));
            request.setDestinationPort(443);
            request.setProtocol("tcp");
            assertEquals(PeerEgressCodes.FORBIDDEN_DESTINATION,
                    PeerEgressAuthorization.evaluate(request, policy, true, context).code(), text);
        }
    }

    private static List<String> strings(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(node -> values.add(node.asText()));
        return values;
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
        return readVector("peer-egress-rules-v1.json");
    }

    private static JsonNode readVector(String fileName) throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/" + fileName);
            if (Files.isRegularFile(candidate)) {
                return JsonUtil.readString(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate " + fileName);
    }
}
