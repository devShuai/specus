package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * Replays {@code peer-egress-windows-routes-v1.json} against the Java Windows route parsers.
 *
 * <p>The cases marked sampled in that file are literal output captured from a Windows 11 machine,
 * not transcribed from documentation, which is the part worth having: these parsers read a format
 * nobody controls, and reading it wrong means installing a route into nothing or deciding a prefix
 * is free when it is not.
 *
 * <p>The expectations come from an independent reference parser in
 * {@code tools/protocol/generate_peer_egress_windows_route_vectors.py}, so agreement is independent
 * agreement rather than three copies of one mistake.
 */
class PeerEgressWindowsRouteVectorTests {

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

    @Test
    void windowsRouteParsingMatchesTheSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-windows-routes-v1.json");
        assertEquals(PeerEgressWindowsRouteCommands.ON_LINK_NEXT_HOP,
                vector.path("onLinkNextHop").asText());

        JsonNode find = vector.path("routeFind");
        assertTrue(find.size() > 0, "vector carried no find cases");
        for (JsonNode testCase : find) {
            String name = testCase.path("name").asText();
            PeerEgressWindowsRouteCommands.Hop hop =
                    PeerEgressWindowsRouteCommands.parseRouteFind(testCase.path("output").asText());
            JsonNode expect = testCase.path("expect");
            if (!expect.path("parsed").asBoolean()) {
                assertNull(hop, name);
                continue;
            }
            assertNotNull(hop, name);
            assertEquals(expect.path("gateway").asText(), hop.gateway(), name + " gateway");
            assertEquals(expect.path("interfaceIndex").asInt(), hop.interfaceIndex(),
                    name + " interface index");
        }

        JsonNode show = vector.path("routeShow");
        assertTrue(show.size() > 0, "vector carried no show cases");
        for (JsonNode testCase : show) {
            String name = testCase.path("name").asText();
            PeerEgressRouteCommands.ExistingRoute existing =
                    PeerEgressWindowsRouteCommands.parseRouteShow(testCase.path("output").asText());
            JsonNode expect = testCase.path("expect");
            assertEquals(expect.path("present").asBoolean(), existing.present(), name + " present");
            assertEquals(expect.path("description").asText(), existing.description(),
                    name + " description");
        }

        JsonNode errors = vector.path("commandErrors");
        assertTrue(errors.size() > 0, "vector carried no error cases");
        for (JsonNode testCase : errors) {
            String name = testCase.path("name").asText();
            assertEquals(testCase.path("expect").path("failure").asText(),
                    PeerEgressWindowsRouteCommands.parseCommandFailure(
                            testCase.path("output").asText()),
                    name);
        }
    }

    /**
     * The scripts are asserted as text, not only by what comes back from running them. Three
     * runtimes each embedding their own PowerShell string is how two of them end up writing to a
     * different policy store than the third, with nothing in the parsed output to show it.
     */
    @Test
    void windowsRouteScriptsMatchTheSharedVector() throws IOException {
        JsonNode scripts = readVector("peer-egress-windows-routes-v1.json").path("scripts");
        assertTrue(scripts.path("showRoutes").size() > 0, "vector carried no script cases");

        for (JsonNode testCase : scripts.path("showRoutes")) {
            assertEquals(testCase.path("expect").asText(),
                    PeerEgressWindowsRouteCommands.showRoutesScript(
                            stringsOf(testCase.path("prefixes"))),
                    testCase.path("name").asText());
        }
        for (JsonNode testCase : scripts.path("findRoutes")) {
            assertEquals(testCase.path("expect").asText(),
                    PeerEgressWindowsRouteCommands.findRoutesScript(
                            stringsOf(testCase.path("addresses"))),
                    testCase.path("name").asText());
        }
        for (JsonNode testCase : scripts.path("installRoute")) {
            assertEquals(testCase.path("expect").asText(),
                    PeerEgressWindowsRouteCommands.installRouteScript(
                            testCase.path("cidr").asText(),
                            testCase.path("interfaceIndex").asInt(),
                            testCase.path("gateway").asText()),
                    testCase.path("name").asText());
        }
        for (JsonNode testCase : scripts.path("removeRoute")) {
            assertEquals(testCase.path("expect").asText(),
                    PeerEgressWindowsRouteCommands.removeRouteScript(testCase.path("cidr").asText()),
                    testCase.path("name").asText());
        }

        // The arguments that must never reach a script. They arrive inside one command string
        // rather than as argv entries, so a quote in a prefix is a second command.
        for (JsonNode testCase : scripts.path("rejectedArguments")) {
            String name = testCase.path("name").asText();
            String value = testCase.path("value").asText();
            boolean prefix = "prefix".equals(testCase.path("kind").asText());
            assertThrows(IllegalArgumentException.class,
                    () -> {
                        if (prefix) {
                            PeerEgressWindowsRouteCommands.showRoutesScript(List.of(value));
                        } else {
                            PeerEgressWindowsRouteCommands.findRoutesScript(List.of(value));
                        }
                    },
                    name + " was accepted into a script");
        }
    }

    /**
     * A batched query writes one line per input, including an empty result, which is what lets the
     * lines be matched back to the prefixes that were asked about.
     */
    @Test
    void scriptLinesSurviveBothLineEndings() {
        List<String> lines = PeerEgressWindowsRouteCommands.splitScriptLines(
                "[]\r\n[{\"InterfaceIndex\":3}]\r\n");
        assertEquals(2, lines.size(), "CRLF output");
        assertEquals("[]", lines.get(0));
        assertEquals(0, PeerEgressWindowsRouteCommands.splitScriptLines("\n\n").size());
    }

    private static List<String> stringsOf(JsonNode array) {
        List<String> values = new ArrayList<>();
        for (JsonNode entry : array) {
            values.add(entry.asText());
        }
        return values;
    }

    /**
     * The adapter name is the one argument that cannot be whitelisted -- it comes from
     * configuration and may legitimately hold spaces and non-ASCII characters -- so it is the one
     * place the escape is load-bearing rather than unreachable.
     */
    @Test
    void windowsInterfaceLookupMatchesTheSharedVector() throws IOException {
        JsonNode vector = readVector("peer-egress-windows-routes-v1.json");
        JsonNode scripts = vector.path("scripts");
        assertTrue(scripts.path("interfaceIndex").size() > 0, "vector carried no interface cases");

        for (JsonNode testCase : scripts.path("interfaceIndex")) {
            assertEquals(testCase.path("expect").asText(),
                    PeerEgressWindowsRouteCommands.interfaceIndexScript(
                            testCase.path("adapter").asText()),
                    testCase.path("name").asText());
            // Nothing a script selects may be anything but ASCII. The child process writes stdout
            // in the console code page, and in GBK the low byte of a character can be a backslash:
            // a name echoed back into the JSON can break the document.
            assertTrue(testCase.path("expect").asText().endsWith("Select-Object InterfaceIndex)"),
                    testCase.path("name").asText() + " selects more than the index");
        }
        assertEquals(scripts.path("showAllRoutes").asText(),
                PeerEgressWindowsRouteCommands.showAllRoutesScript());

        for (JsonNode testCase : vector.path("interfaceIndexParse")) {
            String name = testCase.path("name").asText();
            int index = PeerEgressWindowsRouteCommands.parseInterfaceIndex(
                    testCase.path("output").asText());
            JsonNode expect = testCase.path("expect");
            if (!expect.path("found").asBoolean()) {
                assertEquals(0, index, name);
                continue;
            }
            assertEquals(expect.path("interfaceIndex").asInt(), index, name);
        }
        assertTrue(vector.path("outputEncoding").path("consoleCodePage").asInt() > 0,
                "vector lost the sampled console code page");
    }

    /**
     * The sampled cases are why this vector is worth more than a set of invented strings, so losing
     * them should fail rather than quietly leave a file of guesses behind.
     */
    @Test
    void theVectorKeepsItsSampledCases() throws IOException {
        JsonNode vector = readVector("peer-egress-windows-routes-v1.json");
        int sampled = 0;
        for (String section : new String[] {"routeFind", "routeShow", "commandErrors"}) {
            for (JsonNode testCase : vector.path(section)) {
                if (testCase.path("sampled").asBoolean()) {
                    sampled++;
                }
            }
        }
        assertTrue(sampled >= 10, "vector carries " + sampled + " sampled cases, want at least 10");
    }
}
