package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressRule;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Replays {@code peer-egress-routes-v1.json} against the Java route planner.
 *
 * <p>Unlike the TCP fixture, this one's expectations come from an independent reference planner in
 * {@code tools/protocol/generate_peer_egress_route_vectors.py} rather than from any implementation,
 * so agreeing with it is independent agreement rather than a shared mistake.
 *
 * <p>The operator-visible {@code origin} string is asserted too. Three runtimes that installed the
 * same prefixes but described them differently would still leave an operator unable to compare one
 * machine's log with another's.
 */
class PeerEgressRouteVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode readVector(String name) throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve(name);
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate " + name);
    }

    private static List<PeerEgressRoutePlanner.Route> routesOf(JsonNode array) {
        List<PeerEgressRoutePlanner.Route> routes = new ArrayList<>();
        for (JsonNode node : array) {
            routes.add(new PeerEgressRoutePlanner.Route(
                    node.path("cidr").asText(),
                    PeerEgressRoutePlanner.Kind.fromWireName(node.path("kind").asText()),
                    node.path("origin").asText()));
        }
        return routes;
    }

    private static void assertRoutes(String label, List<PeerEgressRoutePlanner.Route> got, JsonNode want) {
        List<PeerEgressRoutePlanner.Route> expected = routesOf(want);
        assertEquals(expected.size(), got.size(), label + ": route count, got " + got);
        for (int index = 0; index < expected.size(); index++) {
            assertEquals(expected.get(index), got.get(index), label + ": route " + index);
        }
    }

    @Test
    void routePlansMatchTheSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-routes-v1.json");
        String meshCidr = vector.path("meshCidr").asText();
        assertFalse(vector.path("planCases").isEmpty(), "routes vector carried no plan cases");

        for (JsonNode node : vector.path("planCases")) {
            String name = node.path("name").asText();
            List<PeerEgressRule> rules = new ArrayList<>();
            for (JsonNode raw : node.path("rules")) {
                rules.add(MAPPER.treeToValue(raw, PeerEgressRule.class));
            }
            List<String> bypass = new ArrayList<>();
            for (JsonNode raw : node.path("bypass")) {
                bypass.add(raw.asText());
            }

            PeerEgressRoutePlanner.Plan plan = PeerEgressRoutePlanner.plan(rules, bypass, meshCidr);
            assertRoutes(name, plan.routes(), node.path("expect").path("routes"));

            // Asserted alongside the routes because a planner that silently dropped a bad rule
            // would produce exactly the same route list.
            JsonNode wantRefused = node.path("expect").path("refused");
            assertEquals(wantRefused.size(), plan.refused().size(), name + ": refusal count");
            for (int index = 0; index < wantRefused.size(); index++) {
                JsonNode want = wantRefused.get(index);
                PeerEgressRoutePlanner.Refusal got = plan.refused().get(index);
                assertEquals(want.path("index").asInt(), got.index(), name + ": refusal " + index + " index");
                assertEquals(want.path("match").asText(), got.match(), name + ": refusal " + index + " match");
                assertEquals(want.path("code").asText(), got.code(), name + ": refusal " + index + " code");
            }
        }
    }

    @Test
    void routeDiffsMatchTheSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-routes-v1.json");
        assertFalse(vector.path("diffCases").isEmpty(), "routes vector carried no diff cases");

        for (JsonNode node : vector.path("diffCases")) {
            String name = node.path("name").asText();
            PeerEgressRoutePlanner.Difference difference = PeerEgressRoutePlanner.diff(
                    routesOf(node.path("current")), routesOf(node.path("desired")));
            assertRoutes(name + "/remove", difference.remove(), node.path("expect").path("remove"));
            assertRoutes(name + "/add", difference.add(), node.path("expect").path("add"));
        }
    }

    /**
     * The parsers read output formats nobody controls, which makes them the part most likely to be
     * wrong. Each runtime writing its own fixtures from its own reading of the man page is how
     * three readings of one format come about, so all three read these.
     */
    @Test
    void routeCommandParsingMatchesTheSharedVector() throws IOException {
        JsonNode commands = readVector("peer-egress-routes-v1.json").path("routeCommands");
        assertFalse(commands.path("routeGet").isEmpty(), "routes vector carried no routeGet cases");

        for (JsonNode node : commands.path("routeGet")) {
            String name = node.path("name").asText();
            PeerEgressRouteCommands.Hop hop =
                    PeerEgressRouteCommands.parseRouteGet(node.path("output").asText());
            JsonNode expect = node.path("expect");
            if (!expect.path("parsed").asBoolean()) {
                assertNull(hop, name);
                continue;
            }
            assertNotNull(hop, name);
            assertEquals(expect.path("gateway").asText(), hop.gateway(), name);
            assertEquals(expect.path("device").asText(), hop.device(), name);
        }

        assertFalse(commands.path("showExact").isEmpty(), "routes vector carried no showExact cases");
        for (JsonNode node : commands.path("showExact")) {
            String name = node.path("name").asText();
            PeerEgressRouteCommands.ExistingRoute existing =
                    PeerEgressRouteCommands.parseShowExact(node.path("output").asText());
            assertEquals(node.path("expect").path("present").asBoolean(), existing.present(), name);
            assertEquals(node.path("expect").path("description").asText(), existing.description(), name);
        }

        for (JsonNode node : commands.path("tunnelDevice").path("cases")) {
            boolean got = PeerEgressRouteCommands.hopIsDevice(
                    new PeerEgressRouteCommands.Hop("", node.path("device").asText()),
                    node.path("tun").asText());
            String label = node.path("device").asText() + " against " + node.path("tun").asText();
            assertEquals(node.path("expect").asBoolean(), got, label);
        }
        assertTrue(commands.path("tunnelDevice").path("cases").size() > 0,
                "routes vector carried no tunnelDevice cases");
    }
}
