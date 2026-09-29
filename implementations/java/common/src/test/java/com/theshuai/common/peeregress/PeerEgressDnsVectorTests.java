package com.theshuai.common.peeregress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Phase two's consumer decisions, bound to {@code protocol/test-vectors/peer-egress-dns-v1.json}:
 * which rules are valid, which rule a name selects, when phase two runs and what the status says of
 * a rule. The pool, the catalogue and the per-packet steering are replayed in the client, where
 * they live.
 */
class PeerEgressDnsVectorTests {

    private static JsonNode vector() throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/peer-egress-dns-v1.json");
            if (Files.isRegularFile(candidate)) {
                return JsonUtil.readString(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate peer-egress-dns-v1.json");
    }

    private static PeerEgressRule rule(JsonNode node) {
        return JsonUtil.stringToObject(node.toString(), PeerEgressRule.class);
    }

    private static String code(JsonNode node) {
        return node.isNull() || node.isMissingNode() ? null : node.asText();
    }

    /** The pool while phase two runs, as the vector's cases mean "takeover". */
    private static String poolFor(JsonNode document, boolean takeover) {
        return takeover ? document.path("fakeIpCidr").asText() : null;
    }

    @Test
    void constantsMatchTheSharedVector() throws IOException {
        JsonNode document = vector();
        assertEquals(PeerEgressDns.DEFAULT_FAKE_IP_CIDR, document.path("fakeIpCidr").asText());
        assertEquals(PeerEgressRules.DEFAULT_MESH_CIDR, document.path("meshCidr").asText());
        assertEquals(document.path("minLifetimeSeconds").asLong() * 1000, PeerEgressDns.MIN_MAPPING_LIFETIME_MS);
        assertEquals(document.path("quarantineSeconds").asLong() * 1000, PeerEgressDns.QUARANTINE_MS);
    }

    @Test
    void validationMatchesTheSharedVector() throws IOException {
        JsonNode document = vector();
        int checked = 0;
        for (JsonNode testCase : document.path("validation")) {
            String name = testCase.path("name").asText();
            String produced = PeerEgressRules.validate(rule(testCase.path("rule")), document.path("meshCidr").asText(),
                    poolFor(document, testCase.path("takeover").asBoolean()));
            assertEquals(code(testCase.path("code")), produced, name);
            checked++;
        }
        assertTrue(checked > 0, "no validation cases");
    }

    /** Takeover off, a domain rule is refused word for word as in phase one. */
    @Test
    void phaseOneValidationIsUnchangedWithoutAPool() throws IOException {
        JsonNode document = vector();
        for (JsonNode testCase : document.path("validation")) {
            if (testCase.path("takeover").asBoolean()) {
                continue;
            }
            PeerEgressRule rule = rule(testCase.path("rule"));
            assertEquals(PeerEgressRules.validate(rule, document.path("meshCidr").asText()),
                    PeerEgressRules.validate(rule, document.path("meshCidr").asText(), null),
                    testCase.path("name").asText());
        }
    }

    @Test
    void poolConfigMatchesTheSharedVector() throws IOException {
        JsonNode document = vector();
        int checked = 0;
        for (JsonNode testCase : document.path("poolConfig")) {
            assertEquals(code(testCase.path("code")),
                    PeerEgressDns.poolProblem(testCase.path("cidr").asText(), document.path("meshCidr").asText()),
                    testCase.path("name").asText());
            checked++;
        }
        assertTrue(checked > 0, "no poolConfig cases");
    }

    /** The capability check alone, which is ruleStatus for an egress that is online. */
    @Test
    void egressCapabilityMatchesTheSharedVector() throws IOException {
        JsonNode document = vector();
        for (JsonNode testCase : document.path("egressCapability")) {
            boolean capable = testCase.path("egressDomainTargetCapable").asBoolean();
            assertEquals(code(testCase.path("code")),
                    PeerEgressDns.ruleStatus(rule(testCase.path("rule")), document.path("meshCidr").asText(),
                            poolFor(document, true), egress -> true, egress -> capable),
                    testCase.path("name").asText());
        }
    }

    @Test
    void ruleStatusMatchesTheSharedVector() throws IOException {
        JsonNode document = vector();
        int checked = 0;
        for (JsonNode testCase : document.path("ruleStatus")) {
            boolean online = testCase.path("egressOnline").asBoolean();
            boolean capable = testCase.path("egressDomainTargetCapable").asBoolean();
            // The vector's online and capable maps name egress 2 only.
            String produced = PeerEgressDns.ruleStatus(rule(testCase.path("rule")), document.path("meshCidr").asText(),
                    poolFor(document, testCase.path("takeover").asBoolean()),
                    egress -> egress == 2 && online, egress -> egress == 2 && capable);
            assertEquals(code(testCase.path("code")), produced, testCase.path("name").asText());
            checked++;
        }
        assertTrue(checked > 0, "no ruleStatus cases");
    }

    @Test
    void selectionMatchesTheSharedVector() throws IOException {
        JsonNode document = vector();
        List<PeerEgressRule> rules = new ArrayList<>();
        for (JsonNode node : document.path("rules")) {
            rules.add(rule(node));
        }
        int checked = 0;
        for (JsonNode testCase : document.path("selection")) {
            JsonNode expected = testCase.path("ruleIndex");
            Integer produced = PeerEgressDns.selectDomainRule(rules, testCase.path("query").asText(),
                    document.path("meshCidr").asText(), document.path("fakeIpCidr").asText());
            assertEquals(expected.isNull() ? null : expected.asInt(), produced, testCase.path("name").asText());
            checked++;
        }
        assertTrue(checked > 0, "no selection cases");
        // Without phase two no domain rule is valid, so nothing claims a name.
        assertNull(PeerEgressDns.selectDomainRule(rules, "example.com", document.path("meshCidr").asText(), null));
    }

    @Test
    void phaseTwoMatchesTheSharedVector() throws IOException {
        JsonNode document = vector();
        int checked = 0;
        for (JsonNode testCase : document.path("phaseTwo")) {
            String name = testCase.path("name").asText();
            PeerEgressDns.PhaseTwo phase = PeerEgressDns.phaseTwo(testCase.path("consumerEnabled").asBoolean(),
                    testCase.path("takeover").asBoolean(), testCase.path("cidr").asText(),
                    document.path("meshCidr").asText());
            assertEquals(testCase.path("active").asBoolean(), phase.active(), name);
            assertEquals(code(testCase.path("code")), phase.code(), name);
            checked++;
        }
        assertTrue(checked > 0, "no phaseTwo cases");
    }

    /** The pool is judged against the mesh the server actually assigned, not only the default one. */
    @Test
    void phaseTwoChecksThePoolAgainstTheActualMesh() {
        assertTrue(PeerEgressDns.phaseTwo(true, true, "10.0.0.0/8", PeerEgressRules.DEFAULT_MESH_CIDR).active());
        PeerEgressDns.PhaseTwo phase = PeerEgressDns.phaseTwo(true, true, "10.0.0.0/8", "10.200.0.0/16");
        assertFalse(phase.active());
        assertEquals(PeerEgressCodes.FAKE_IP_POOL_INVALID, phase.code());
    }

    /** A match that is neither an address nor a name stays malformed, and rules report their kind. */
    @Test
    void kindsAndNonNames() {
        PeerEgressRule digits = new PeerEgressRule();
        digits.setMatch("1.2.3.4-5");
        digits.setAction(PeerEgressRule.ACTION_DIRECT);
        assertEquals(PeerEgressCodes.RULE_MALFORMED,
                PeerEgressRules.validate(digits, PeerEgressRules.DEFAULT_MESH_CIDR, PeerEgressDns.DEFAULT_FAKE_IP_CIDR));
        assertEquals(PeerEgressCodes.RULE_DOMAIN_UNSUPPORTED,
                PeerEgressRules.validate(digits, PeerEgressRules.DEFAULT_MESH_CIDR));

        PeerEgressRule domain = new PeerEgressRule();
        domain.setMatch("*.example.com");
        PeerEgressRule address = new PeerEgressRule();
        address.setMatch("203.0.113.0/24");
        PeerEgressRule ipv6 = new PeerEgressRule();
        ipv6.setMatch("2001:db8::/32");
        assertEquals(PeerEgressRules.KIND_DOMAIN, PeerEgressRules.kind(domain));
        assertEquals(PeerEgressRules.KIND_CIDR, PeerEgressRules.kind(address));
        assertEquals(PeerEgressRules.KIND_CIDR, PeerEgressRules.kind(ipv6));
    }
}
