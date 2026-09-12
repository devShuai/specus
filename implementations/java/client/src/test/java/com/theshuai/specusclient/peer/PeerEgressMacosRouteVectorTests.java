package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Replays {@code peer-egress-macos-routes-v1.json} against the Java macOS route readings.
 *
 * <p>Everything marked sampled in that file is literal output captured from a real macOS machine,
 * and three of those captures changed the design rather than confirming it: {@code route} exits 0
 * when it fails, it accepts a /33 and installs half the IPv4 address space, and the readings are
 * cheap enough that caching them would buy nothing.
 *
 * <p>The expectations come from an independent reference implementation in
 * {@code tools/protocol/generate_peer_egress_macos_route_vectors.py}, so agreement here is
 * independent agreement rather than three copies of one mistake.
 */
class PeerEgressMacosRouteVectorTests {

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

    private static JsonNode vector() throws IOException {
        return readVector("peer-egress-macos-routes-v1.json");
    }

    /**
     * {@code route -n get} is how a bypass next hop is found, and the reading that matters is that
     * an on-link destination has no gateway line at all -- not even the gateway's own address,
     * which has a cloned entry carrying a MAC address.
     */
    @Test
    void routeGetMatchesTheSharedVector() throws IOException {
        JsonNode cases = vector().path("routeGet");
        assertTrue(cases.size() > 0, "vector carried no route-get cases");
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            PeerEgressRouteCommands.Hop hop = PeerEgressMacosRouteCommands.parseRouteGet(
                    testCase.path("stdout").asText(), testCase.path("stderr").asText());
            JsonNode expect = testCase.path("expect");
            if (!expect.path("parsed").asBoolean()) {
                assertNull(hop, name);
                continue;
            }
            assertNotNull(hop, name);
            assertEquals(expect.path("gateway").asText(), hop.gateway(), name);
            assertEquals(expect.path("interface").asText(), hop.device(), name);
        }
    }

    /**
     * netstat abbreviates the destination column and the abbreviations are not guessable: "127" is
     * a /8, "203.0.113" is a /24, "100.64/10" fills in the missing octet. Reading one wrong means
     * the conflict check compares against a prefix nobody asked about.
     */
    @Test
    void prefixNormalisationMatchesTheSharedVector() throws IOException {
        JsonNode cases = vector().path("normalisePrefix").path("cases");
        assertTrue(cases.size() > 0, "vector carried no normalisation cases");
        for (JsonNode testCase : cases) {
            String input = testCase.path("input").asText();
            assertEquals(testCase.path("expect").asText(),
                    PeerEgressMacosRouteCommands.normalisePrefix(input), input);
        }
    }

    /** Which rows of {@code netstat -rn} are routes, and which section they have to come from. */
    @Test
    void tableParsingMatchesTheSharedVector() throws IOException {
        JsonNode root = vector();
        for (String section : List.of("table", "bothFamilies", "duplicates", "tunRoute")) {
            JsonNode testCase = root.path(section);
            assertTrue(testCase.path("stdout").asText().length() > 0, section);
            List<PeerEgressMacosRouteCommands.NetstatRoute> routes =
                    PeerEgressMacosRouteCommands.parseTable(testCase.path("stdout").asText());
            JsonNode expect = testCase.path("expect");
            assertEquals(expect.path("rows").asInt(), routes.size(), section);
            List<String> prefixes = new ArrayList<>();
            for (PeerEgressMacosRouteCommands.NetstatRoute route : routes) {
                prefixes.add(route.prefix());
            }
            List<String> wanted = new ArrayList<>();
            for (JsonNode prefix : expect.path("prefixes")) {
                wanted.add(prefix.asText());
            }
            assertEquals(wanted, prefixes, section);
        }
        // The two-family table has to yield the same routes as the IPv4-only one: "default" is the
        // one destination whose IPv6 spelling is indistinguishable from its IPv4 spelling, and the
        // sampling machine had four of them, one per utun.
        assertEquals(root.path("table").path("expect").path("prefixes"),
                root.path("bothFamilies").path("expect").path("prefixes"),
                "the two-family table is expected to carry the same routes as the IPv4 one");
    }

    /** The conflict check, which decides whether a rule is applied or refused. */
    @Test
    void conflictFromTableMatchesTheSharedVector() throws IOException {
        JsonNode section = vector().path("conflictFromTable");
        JsonNode cases = section.path("cases");
        assertTrue(cases.size() > 0, "vector carried no conflict cases");
        for (JsonNode testCase : cases) {
            String prefix = testCase.path("prefix").asText();
            String tableName = testCase.path("table").asText();
            JsonNode table = section.path("tables").path(tableName);
            assertFalse(table.isMissingNode(), "vector names a table it does not carry: "
                    + tableName);
            PeerEgressRouteCommands.ExistingRoute existing =
                    PeerEgressMacosRouteCommands.conflictFromTable(table.asText(), prefix);
            JsonNode expect = testCase.path("expect");
            String label = prefix + " in " + tableName;
            assertEquals(expect.path("present").asBoolean(), existing.present(), label);
            assertEquals(expect.path("existing").asText(), existing.description(), label);
        }
    }

    /** Whether a mutation worked, which cannot be read from the exit status. */
    @Test
    void commandResultsMatchTheSharedVector() throws IOException {
        JsonNode root = vector();
        assertEquals(PeerEgressMacosRouteCommands.KERNEL_GENERATED_FLAG,
                root.path("kernelGeneratedFlag").asText());
        assertEquals(PeerEgressMacosRouteCommands.FAILURE_PERMISSION_DENIED,
                root.path("failureKinds").path("denied").asText());
        assertEquals(PeerEgressMacosRouteCommands.FAILURE_OTHER,
                root.path("failureKinds").path("other").asText());

        JsonNode cases = root.path("commandResults");
        assertTrue(cases.size() > 0, "vector carried no command results");
        int zeroExitFailures = 0;
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            assertEquals(testCase.path("expect").path("failure").asText(),
                    PeerEgressMacosRouteCommands.classifyFailure(
                            testCase.path("stdout").asText(), testCase.path("stderr").asText()),
                    name);
            if (testCase.path("exit").asInt() == 0
                    && !testCase.path("expect").path("failure").asText().isEmpty()) {
                zeroExitFailures++;
            }
        }
        // The reason none of this reads the exit status. Without a case like this an implementation
        // could check it and pass the whole file.
        assertTrue(zeroExitFailures > 0, "the vector no longer carries a failure that exited 0");
    }

    /**
     * The argv arrays are pinned as well as their output. Three runtimes each assembling their own
     * arguments is exactly how two of them end up using -net while the third uses -host, with
     * nothing in the parsed output to show it.
     */
    @Test
    void commandsMatchTheSharedVector() throws IOException {
        JsonNode commands = vector().path("commands");
        assertEquals(asList(commands.path("showTable")),
                PeerEgressMacosRouteCommands.showTableArgs());
        for (JsonNode testCase : commands.path("findRoute")) {
            assertEquals(asList(testCase.path("argv")),
                    PeerEgressMacosRouteCommands.findRouteArgs(
                            testCase.path("address").asText()));
        }
        for (JsonNode testCase : commands.path("installInterface")) {
            assertEquals(asList(testCase.path("argv")),
                    PeerEgressMacosRouteCommands.installInterfaceArgs(
                            testCase.path("prefix").asText(),
                            testCase.path("interface").asText()));
        }
        for (JsonNode testCase : commands.path("installGateway")) {
            assertEquals(asList(testCase.path("argv")),
                    PeerEgressMacosRouteCommands.installGatewayArgs(
                            testCase.path("prefix").asText(),
                            testCase.path("gateway").asText()));
        }
        for (JsonNode testCase : commands.path("remove")) {
            assertEquals(asList(testCase.path("argv")),
                    PeerEgressMacosRouteCommands.removeArgs(testCase.path("prefix").asText()));
        }
    }

    /**
     * What has to be refused. The one that matters is 203.0.113.0/33: {@code route} accepts it,
     * prints a success line naming 203.0.113.0, exits 0, and installs 128.0/1.
     */
    @Test
    void refusedArgumentsMatchTheSharedVector() throws IOException {
        JsonNode cases = vector().path("commands").path("rejectedArguments");
        assertTrue(cases.size() > 0, "vector carried no refused arguments");
        for (JsonNode testCase : cases) {
            String kind = testCase.path("kind").asText();
            String value = testCase.path("value").asText();
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> {
                        switch (kind) {
                            case "prefix" -> PeerEgressMacosRouteCommands
                                    .installInterfaceArgs(value, "utun3");
                            case "address" -> PeerEgressMacosRouteCommands.findRouteArgs(value);
                            case "interface" -> PeerEgressMacosRouteCommands
                                    .installInterfaceArgs("203.0.113.0/24", value);
                            default -> throw new IllegalStateException(
                                    "vector asks about an argument kind nothing builds: " + kind);
                        }
                    }, kind + " " + value);
            assertTrue(refused.getMessage().contains(PeerEgressMacosRouteCommands.REFUSAL),
                    refused.getMessage());
        }
        // Withdrawal validates too. A removal built from a prefix nobody checked is a removal of
        // whatever `route` decides that text means.
        assertThrows(IllegalArgumentException.class,
                () -> PeerEgressMacosRouteCommands.removeArgs("203.0.113.0/33"));
    }

    /**
     * The capture that says why the prefix is validated before a process starts, kept as a test so
     * the evidence travels with the rule rather than living only in a commit message.
     */
    @Test
    void aMalformedPrefixWouldInstallHalfTheInternet() throws IOException {
        JsonNode section = vector().path("malformedPrefix");
        String installed = section.path("installedPrefix").asText();
        assertTrue(installed.length() > 0, "vector carried no malformed-prefix evidence");
        // `route` reported success, and what it says it did names a different prefix than what it
        // did.
        assertEquals(0, section.path("exit").asInt(),
                "the malformed add failed, so the argument check is not the only defence");
        assertFalse(section.path("stdout").asText().contains(installed),
                "the output names " + installed + " after all, so this evidence is stale");
        assertTrue(PeerEgressMacosRouteCommands.conflictFromTable(
                section.path("tableAfter").asText(), installed).present(),
                installed + " is not in the table the malformed add left behind");
        assertFalse(PeerEgressMacosRouteCommands.validPrefix("203.0.113.0/33"),
                "the argument that installs half the internet is accepted");
    }

    /**
     * The measurement that says not to cache, asserted so a cache cannot be added without the
     * number that justifies it.
     */
    @Test
    void theConflictCheckDoesNotCache() throws IOException {
        assertFalse(vector().path("timings").path("cache").asBoolean(),
                "the vector now expects a cached table; the commander does not keep one");
    }

    private static List<String> asList(JsonNode array) {
        List<String> values = new ArrayList<>();
        for (JsonNode entry : array) {
            values.add(entry.asText());
        }
        return values;
    }
}
