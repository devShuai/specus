package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.specusclient.cli.EgressView;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the status surface has to be able to say, and what a person is shown.
 *
 * <p>The three things it exists for are a rule that is configured and not in force, a route this
 * feature wanted and did not get, and an egress peer a rule names that is offline. Each of those is
 * a way for the feature to be doing nothing while every other surface looks healthy, so each one
 * gets a case here.
 *
 * <p>The shape is the one the Go client writes, because either CLI reads whichever wrote the state
 * file. {@code protocol/spec/peer-egress.md} is where the shape is pinned.
 */
class PeerEgressStatusTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path directory;

    private PeerEgressMesh mesh;

    @AfterEach
    void stop() {
        if (mesh != null) {
            mesh.close();
        }
    }

    /** A routing table whose answers this test chooses. */
    private static final class ChosenCommander implements PeerEgressRouteInstaller.Commander {
        private final Map<String, String> owned;

        ChosenCommander(Map<String, String> owned) {
            this.owned = owned;
        }

        @Override
        public PeerEgressRouteInstaller.Conflict conflict(PeerEgressRoutePlanner.Route route) {
            String existing = owned.get(route.cidr());
            return existing == null
                    ? PeerEgressRouteInstaller.Conflict.none()
                    : new PeerEgressRouteInstaller.Conflict(true, existing);
        }

        @Override
        public void install(PeerEgressRoutePlanner.Route route) {
        }

        @Override
        public void remove(PeerEgressRoutePlanner.Route route) {
        }
    }

    private final class Host implements PeerEgressMesh.Host {
        @Override
        public boolean sendToPeer(long peerId, byte[] frame) {
            return true;
        }

        @Override
        public void writeToDevice(byte[] packet) {
        }

        @Override
        public String tunName() {
            return "specus0";
        }

        @Override
        public String meshCidr() {
            return "100.96.0.0/11";
        }

        @Override
        public String virtualIp() {
            return "100.96.0.7";
        }

        @Override
        public List<String> deploymentDenyCidrs() {
            return List.of();
        }

        @Override
        public List<String> peerEndpointAddresses() {
            return List.of("198.51.100.240");
        }

        @Override
        public Integer pathMtuForPeer(long peerId) {
            return null;
        }

        @Override
        public Path routeJournalPath() {
            return directory.resolve("egress-routes.json");
        }
    }

    private PeerEgressMesh meshOwning(Map<String, String> owned) {
        mesh = new PeerEgressMesh(new Host(), (protocol, host, port, timeoutMs) -> {
            throw new IOException("nothing is dialled in this test");
        }, new ChosenCommander(owned));
        return mesh;
    }

    private static PeerEgressRule rule(String match, String action, Long target) {
        PeerEgressRule value = new PeerEgressRule();
        value.setMatch(match);
        value.setAction(action);
        value.setEgressClientId(target);
        return value;
    }

    private JsonNode section(PeerEgressMesh subject) {
        return MAPPER.valueToTree(subject.status());
    }

    /**
     * A refused rule is reported as refused, with its code, rather than being left out.
     *
     * <p>Left out is the failure that matters: an operator who wrote a rule and reads a status
     * listing only the rules that worked has no way to see that the one they care about is text in
     * a file.
     */
    @Test
    void aRuleThatIsNotInForceIsReportedAsSuch() {
        PeerEgressMesh subject = meshOwning(Map.of());
        subject.applyRules(List.of(
                rule("203.0.113.0/24", PeerEgressRule.ACTION_EGRESS, 42L),
                // Refused: phase one does not take over the default route.
                rule("0.0.0.0/0", PeerEgressRule.ACTION_EGRESS, 42L)));

        JsonNode consumer = section(subject).path("consumer");
        assertTrue(consumer.path("active").asBoolean(), "the consumer reports itself inactive");
        JsonNode rules = consumer.path("rules");
        assertEquals(2, rules.size());
        assertTrue(rules.get(0).path("inForce").asBoolean(), "the usable rule is not in force");
        assertTrue(rules.get(0).path("code").isMissingNode(),
                "the usable rule carries a refusal code");
        assertFalse(rules.get(1).path("inForce").asBoolean(),
                "the default-route rule is reported as in force");
        assertEquals(PeerEgressCodes.RULE_DEFAULT_ROUTE, rules.get(1).path("code").asText());
    }

    /**
     * A refused rule contributes no egress peer. Reporting one would advertise a peer this node
     * will never send to, which reads as a healthy destination for a rule that steers nothing.
     */
    @Test
    void aRefusedRuleContributesNoEgressPeer() {
        PeerEgressMesh subject = meshOwning(Map.of());
        subject.applyRules(List.of(rule("0.0.0.0/0", PeerEgressRule.ACTION_EGRESS, 77L)));

        assertEquals(0, section(subject).path("consumer").path("peers").size(),
                "a refused rule contributed an egress peer");
    }

    /** A route refused because something already owned the prefix is listed, not dropped. */
    @Test
    void aRouteThatWasNotInstalledIsReported() {
        String existing = "203.0.113.0/24 via 192.0.2.1 dev eth0";
        PeerEgressMesh subject = meshOwning(Map.of("203.0.113.0/24", existing));
        subject.applyRules(List.of(rule("203.0.113.0/24", PeerEgressRule.ACTION_EGRESS, 42L)));

        JsonNode consumer = section(subject).path("consumer");
        JsonNode contested = null;
        for (JsonNode route : consumer.path("routes")) {
            if (route.path("cidr").asText().equals("203.0.113.0/24")) {
                contested = route;
            }
        }
        assertNotNull(contested, "the contested route is missing from " + consumer.path("routes"));
        assertFalse(contested.path("installed").asBoolean(),
                "the contested route is reported as installed");
        assertEquals(existing, contested.path("conflict").asText());
        assertTrue(consumer.has("appliedAtUnixMs"), "the section does not say when it was applied");
    }

    /**
     * Before anything has been applied the section says so, rather than reporting an empty rule
     * set, which would read as "configured and nothing matched".
     */
    @Test
    void neverAppliedReadsDifferentlyFromNothingConfigured() {
        JsonNode consumer = section(meshOwning(Map.of())).path("consumer");
        assertFalse(consumer.path("active").asBoolean(),
                "the consumer reports itself active before any rules were applied");
        assertFalse(consumer.has("appliedAtUnixMs"),
                "an apply time is reported before any apply happened");
    }

    /** The egress role's own half: not serving until a policy enables it. */
    @Test
    void whetherThisNodeIsServingIsReported() {
        PeerEgressMesh subject = meshOwning(Map.of());
        assertFalse(section(subject).path("egress").path("active").asBoolean(),
                "the egress reports itself serving before any policy arrived");

        subject.applyEgressConfig("""
                {"type":"egress-config","enabled":true,"revision":3,"scope":"PUBLIC",
                 "allowedConsumerClientIds":[5],
                 "destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp"],
                                      "portRanges":[[443,443]]}],
                 "limits":{"maxConcurrentFlows":256,"maxFlowsPerConsumer":64,
                           "idleTimeoutSeconds":60}}""");

        JsonNode egress = section(subject).path("egress");
        assertTrue(egress.path("active").asBoolean(), "the egress does not report itself serving");
        assertEquals(3L, egress.path("revision").asLong());
    }

    /**
     * What a person is shown: the problems, and a count of the rest.
     *
     * <p>Rendered from the same section the JSON form carries, so this is also the check that the
     * two do not disagree about which rule is broken.
     */
    @Test
    void theViewNamesTheProblemsAndCountsTheRest() {
        String existing = "203.0.113.0/24 via 192.0.2.1 dev eth0";
        PeerEgressMesh subject = meshOwning(Map.of("203.0.113.0/24", existing));
        subject.applyRules(List.of(
                rule("203.0.113.0/24", PeerEgressRule.ACTION_EGRESS, 42L),
                rule("0.0.0.0/0", PeerEgressRule.ACTION_EGRESS, 42L)));

        String output = String.join("\n", EgressView.lines(section(subject)));
        assertTrue(output.contains("2 rules (1 not in force)"), output);
        assertTrue(output.contains("rule 1 \"0.0.0.0/0\": NOT IN FORCE ("
                + PeerEgressCodes.RULE_DEFAULT_ROUTE + ")"), output);
        assertTrue(output.contains("NOT INSTALLED, already present: " + existing), output);
        // The peer named by the rule that is in force has never been reported online.
        assertTrue(output.contains("egress peer 42: offline"), output);
        assertTrue(output.contains("egress: not serving"), output);
    }

    /**
     * The state file may have been written by the Go or .NET client, so a missing or wrongly typed
     * field has to produce a line rather than an exception. A status command that failed on a field
     * somebody spelled differently would be worse than one that prints a zero.
     */
    @Test
    void theViewToleratesStateItDidNotWrite() throws Exception {
        for (String document : List.of(
                "{}",
                "{\"consumer\":null,\"egress\":null}",
                "{\"consumer\":{\"active\":true,\"rules\":\"not a list\",\"routes\":7,"
                        + "\"peers\":{},\"flows\":\"three\",\"blocked\":[1,2]},"
                        + "\"egress\":{\"active\":\"yes\"}}",
                "{\"consumer\":{\"active\":true,\"rules\":[null,5,{\"inForce\":\"maybe\"}],"
                        + "\"routes\":[{\"installed\":null}]},"
                        + "\"egress\":{\"active\":true,\"flows\":null}}")) {
            assertFalse(EgressView.lines(MAPPER.readTree(document)).isEmpty(),
                    "produced no output: " + document);
        }
        List<String> missing = EgressView.lines(null);
        assertEquals(1, missing.size());
        assertTrue(missing.get(0).contains("No egress state"), missing.toString());
    }
}
