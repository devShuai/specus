package com.theshuai.specusclient.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import org.junit.jupiter.api.Test;

/**
 * The egress editing commands with phase two configured: rules are judged as the running client
 * would judge them, offline (the master switch taken as on, the default mesh), and the new code is
 * explained in the words the Go and .NET clients print.
 */
class EgressEditPhaseTwoTests {

    private static ClientStartupConfig config(String extra) throws Exception {
        return ClientCli.parse("{\"serverBaseUrl\":\"https://example.invalid\",\"apiKey\":\"k\",\"secret\":\"s\""
                + extra + "}", ignored -> { });
    }

    private static PeerEgressRule rule(String match, String action) {
        PeerEgressRule value = new PeerEgressRule();
        value.setMatch(match);
        value.setAction(action);
        return value;
    }

    @Test
    void explainsThePoolOverlapInTheSharedWords() {
        assertEquals("overlaps the fake-IP pool (peerEgressFakeIpCidr), whose addresses only domain rules hand out",
                EgressEdit.explanation(PeerEgressCodes.RULE_FAKE_IP_OVERLAP));
    }

    @Test
    void judgesRulesAgainstThePoolPhaseTwoWouldRunWith() throws Exception {
        // The master switch is off: offline, the pool is judged as though it were on.
        ClientStartupConfig takeover = config(",\"peerEgressDnsTakeover\":true");
        assertNull(EgressEdit.ruleCode(takeover, rule("*.example.com", "block")));
        assertEquals(PeerEgressCodes.RULE_FAKE_IP_OVERLAP, EgressEdit.ruleCode(takeover, rule("198.18.1.0/24", "block")));
        assertEquals(PeerEgressCodes.CONSUMER_DISABLED, EgressEdit.statusCode(takeover, rule("*.example.com", "block")));

        ClientStartupConfig off = config("");
        assertEquals(PeerEgressCodes.RULE_DOMAIN_UNSUPPORTED, EgressEdit.ruleCode(off, rule("*.example.com", "block")));
        assertNull(EgressEdit.ruleCode(off, rule("198.18.1.0/24", "block")));

        // An empty pool setting is the default one.
        ClientStartupConfig blank = config(",\"peerEgressDnsTakeover\":true,\"peerEgressFakeIpCidr\":\"\"");
        assertEquals("198.18.0.0/15", blank.getPeerEgressFakeIpCidr());
        assertNull(EgressEdit.ruleCode(blank, rule("example.com", "direct")));
    }

    @Test
    void addsADomainRuleOnlyWhenPhaseTwoWouldTakeIt() throws Exception {
        EgressEdit.Change add = new EgressEdit.Change("add", "*.example.com", "block", 0, -1, -1, -1,
                false, false, false);
        EgressEdit.Planned planned = EgressEdit.plan(config(",\"peerEgressDnsTakeover\":true"), add);
        assertTrue(planned.value().contains("\"*.example.com\""), planned.value());

        EgressEdit.PlanFailure refused = assertThrows(EgressEdit.PlanFailure.class,
                () -> EgressEdit.plan(config(",\"peerEgressDnsTakeover\":true"),
                        new EgressEdit.Change("add", "198.18.4.0/24", "block", 0, -1, -1, -1, false, false, false)));
        assertEquals("Rule not added: EGRESS_RULE_FAKE_IP_OVERLAP (overlaps the fake-IP pool (peerEgressFakeIpCidr),"
                + " whose addresses only domain rules hand out)", refused.getMessage());
    }
}
