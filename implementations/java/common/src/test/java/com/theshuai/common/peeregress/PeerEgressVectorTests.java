package com.theshuai.common.peeregress;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Binds this implementation to the shared vectors under {@code protocol/test-vectors}.
 *
 * <p>The assertions check the returned code, not just allow versus deny: a runtime that denies for
 * the wrong reason would still leave operators unable to tell a revoked ACL from a closed port.
 */
class PeerEgressVectorTests {
    @Test
    void authorizationMatchesSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-authz-v1.json");
        PeerEgressPolicy basePolicy = policyOf(vector.path("policy"));
        PeerEgressAuthorization.Context context = contextOf(vector);
        int checked = 0;
        for (JsonNode node : vector.path("cases")) {
            PeerEgressRequest request = requestOf(node.path("request"));
            PeerEgressAuthorization.Decision decision =
                    PeerEgressAuthorization.evaluate(request, basePolicy, true, context);
            String name = node.path("name").asText();
            assertEquals(node.path("expect").path("code").asText(), decision.code(), name);
            assertEquals(node.path("expect").path("allowed").asBoolean(), decision.allowed(), name);
            checked++;
        }
        assertTrue(checked > 0, "authorization vector carried no cases");
    }

    /**
     * Boundary sweep shared by every runtime.
     *
     * <p>The hand-written cases document intent; this exists to catch a runtime that agrees on the
     * documented examples but diverges one address or one port away from a boundary. Every runtime
     * runs the same sweep against the same policy, so a disagreement here is a disagreement about
     * the rules rather than about the fixture.
     */
    @Test
    void crossLanguageBoundarySweepMatchesSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-authz-v1.json");
        PeerEgressPolicy basePolicy = policyOf(vector.path("policy"));
        PeerEgressAuthorization.Context context = contextOf(vector);
        int checked = 0;
        for (JsonNode node : vector.path("crossLanguageCases")) {
            PeerEgressRequest request = requestOf(node.path("request"));
            PeerEgressAuthorization.Decision decision =
                    PeerEgressAuthorization.evaluate(request, basePolicy, true, context);
            String name = node.path("name").asText();
            assertEquals(node.path("expect").path("code").asText(), decision.code(), name);
            assertEquals(node.path("expect").path("allowed").asBoolean(), decision.allowed(), name);
            checked++;
        }
        assertTrue(checked >= 100, "cross-language sweep carried only " + checked + " cases");
    }

    @Test
    void policyVariantsMatchSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-authz-v1.json");
        PeerEgressAuthorization.Context context = contextOf(vector);
        int checked = 0;
        for (JsonNode node : vector.path("policyVariantCases")) {
            PeerEgressPolicy policy = policyOf(vector.path("policy"));
            JsonNode override = node.path("policyOverride");
            if (override.isObject()) {
                if (override.has("enabled")) {
                    policy.setEnabled(override.path("enabled").asBoolean());
                }
                if (override.has("scope")) {
                    policy.setScope(override.path("scope").asText());
                }
                if (override.has("destinationRules")) {
                    policy.setDestinationRules(destinationRulesOf(override.path("destinationRules")));
                }
            }
            boolean peerAclAllows = !node.has("peerAclAllows") || node.path("peerAclAllows").asBoolean();
            PeerEgressRequest request = requestOf(node.path("request"));
            PeerEgressAuthorization.Decision decision =
                    PeerEgressAuthorization.evaluate(request, policy, peerAclAllows, context);
            String name = node.path("name").asText();
            assertEquals(node.path("expect").path("code").asText(), decision.code(), name);
            checked++;
        }
        assertTrue(checked > 0, "authorization vector carried no policy variants");
    }

    /**
     * The vector's policy deliberately contains a {@code 0.0.0.0/0} rule. Every address the vector
     * declares as forced-deny must still be refused through it.
     */
    @Test
    void forcedDenyDestinationsSurviveABroadAllowRule() throws IOException {
        JsonNode vector = readVector("peer-egress-authz-v1.json");
        PeerEgressPolicy policy = policyOf(vector.path("policy"));
        PeerEgressAuthorization.Context context = contextOf(vector);
        assertTrue(policy.getDestinationRules().stream().anyMatch(rule -> "0.0.0.0/0".equals(rule.getCidr())),
                "vector policy must keep a broad rule, otherwise this test proves nothing");

        List<String> denied = new ArrayList<>();
        for (JsonNode node : vector.path("forcedDenyCidrs")) {
            denied.add(node.asText());
        }
        for (JsonNode node : vector.path("cloudMetadataCidrs")) {
            denied.add(node.asText());
        }
        assertFalse(denied.isEmpty(), "vector declared no forced-deny ranges");

        for (String text : denied) {
            Ipv4Cidr cidr = Ipv4Cidr.parse(text);
            assertNotNull(cidr, text);
            PeerEgressRequest request = new PeerEgressRequest();
            request.setConsumerClientId(1);
            request.setDestinationIp(Ipv4Cidr.format(cidr.network()));
            request.setDestinationPort(443);
            request.setProtocol("tcp");
            PeerEgressAuthorization.Decision decision =
                    PeerEgressAuthorization.evaluate(request, policy, true, context);
            assertEquals(PeerEgressCodes.FORBIDDEN_DESTINATION, decision.code(), text);
        }
    }

    @Test
    void ruleMatchingMatchesSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-rules-v1.json");
        List<PeerEgressRule> rules = new ArrayList<>();
        for (JsonNode node : vector.path("rules")) {
            rules.add(JsonUtil.stringToObject(node.toString(), PeerEgressRule.class));
        }
        assertFalse(rules.isEmpty(), "rules vector carried no rules");

        for (JsonNode node : vector.path("cases")) {
            String name = node.path("name").asText();
            PeerEgressRules.Match match = PeerEgressRules.match(rules, node.path("destination").asText());
            JsonNode expect = node.path("expect");
            assertEquals(expect.path("action").asText(), match.action(), name);
            if (expect.path("matchedRuleIndex").isNull()) {
                assertNull(match.matchedRuleIndex(), name);
                assertFalse(match.matched(), name);
            } else {
                assertEquals(expect.path("matchedRuleIndex").asInt(), match.matchedRuleIndex(), name);
            }
            if (expect.has("egressClientId")) {
                assertEquals(expect.path("egressClientId").asLong(), match.egressClientId(), name);
            }
        }
    }

    @Test
    void ruleValidationMatchesSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-rules-v1.json");
        String meshCidr = vector.path("meshCidr").asText(PeerEgressRules.DEFAULT_MESH_CIDR);

        for (JsonNode node : vector.path("rules")) {
            PeerEgressRule rule = JsonUtil.stringToObject(node.toString(), PeerEgressRule.class);
            assertNull(PeerEgressRules.validate(rule, meshCidr),
                    "rule " + node.path("match").asText() + " must pass validation");
        }

        int checked = 0;
        for (JsonNode node : vector.path("configValidation")) {
            PeerEgressRule rule = JsonUtil.stringToObject(node.path("rule").toString(), PeerEgressRule.class);
            assertEquals(node.path("code").asText(), PeerEgressRules.validate(rule, meshCidr),
                    node.path("name").asText());
            checked++;
        }
        assertTrue(checked > 0, "rules vector carried no configValidation cases");
    }

    private static PeerEgressAuthorization.Context contextOf(JsonNode vector) {
        String meshCidr = PeerEgressRules.DEFAULT_MESH_CIDR;
        for (JsonNode node : vector.path("forcedDenyCidrs")) {
            Ipv4Cidr cidr = Ipv4Cidr.parse(node.asText());
            if (cidr != null && cidr.prefixLength() == 11) {
                meshCidr = node.asText();
            }
        }
        return new PeerEgressAuthorization.Context(meshCidr, List.of());
    }

    private static PeerEgressPolicy policyOf(JsonNode node) {
        return JsonUtil.stringToObject(node.toString(), PeerEgressPolicy.class);
    }

    private static PeerEgressRequest requestOf(JsonNode node) {
        return JsonUtil.stringToObject(node.toString(), PeerEgressRequest.class);
    }

    private static List<PeerEgressPolicy.PeerEgressDestinationRule> destinationRulesOf(JsonNode node) {
        List<PeerEgressPolicy.PeerEgressDestinationRule> rules = new ArrayList<>();
        for (JsonNode entry : node) {
            rules.add(JsonUtil.stringToObject(entry.toString(),
                    PeerEgressPolicy.PeerEgressDestinationRule.class));
        }
        return rules;
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
