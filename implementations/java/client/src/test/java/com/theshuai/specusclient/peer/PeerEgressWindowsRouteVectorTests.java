package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
        assertTrue(sampled >= 9, "vector carries " + sampled + " sampled cases, want at least 9");
    }
}
