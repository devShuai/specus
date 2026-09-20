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
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Replays {@code peer-egress-socket-binding-v1.json} against the Java choice of interface for an
 * egress socket and the two platforms' table readings.
 *
 * <p>The expectations come from an independent reference in
 * {@code tools/protocol/generate_peer_egress_socket_binding_vectors.py}, whose Windows tables are
 * built from the SDK's structure layouts with ctypes and whose macOS tables are sampled captures.
 */
class PeerEgressSocketBindingVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors")
                    .resolve("peer-egress-socket-binding-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-socket-binding-v1.json");
    }

    private static List<PeerEgressSocketBinding.Route> routes(JsonNode array) {
        List<PeerEgressSocketBinding.Route> routes = new ArrayList<>();
        for (JsonNode route : array) {
            routes.add(new PeerEgressSocketBinding.Route(route.path("prefix").asText(),
                    route.path("interface").asText(), route.path("gateway").asText(""),
                    route.path("metric").asLong(), route.path("usable").asBoolean()));
        }
        return routes;
    }

    private static void assertChoice(String name, List<PeerEgressSocketBinding.Route> routes, JsonNode testCase) {
        JsonNode expected = testCase.path("expect").path("interface");
        String chosen = PeerEgressSocketBinding.select(routes, testCase.path("tunnel").asText(),
                testCase.path("destination").asText());
        if (expected.isNull()) {
            assertNull(chosen, name + ": want the dial refused");
        } else {
            assertEquals(expected.asText(), chosen, name);
        }
    }

    @Test
    void selectionMatchesTheSharedVector() throws IOException {
        JsonNode cases = vector().path("select").path("cases");
        assertTrue(cases.size() > 0, "no selection cases");
        for (JsonNode testCase : cases) {
            assertChoice(testCase.path("name").asText(), routes(testCase.path("routes")), testCase);
        }
    }

    @Test
    void windowsTablesMatchTheSharedVector() throws IOException {
        JsonNode windows = vector().path("windows");
        Map<String, List<PeerEgressSocketBinding.WindowsForwardRow>> forwardByName = new HashMap<>();
        for (JsonNode table : windows.path("forwardTables")) {
            String name = table.path("name").asText();
            var rows = PeerEgressSocketBinding.parseWindowsForwardTable(
                    HexFormat.of().parseHex(table.path("hex").asText()));
            assertEquals(table.path("expect").path("parsed").asBoolean(), rows != null, "forward " + name);
            if (rows == null) {
                continue;
            }
            List<PeerEgressSocketBinding.WindowsForwardRow> expected = new ArrayList<>();
            for (JsonNode row : table.path("expect").path("rows")) {
                expected.add(new PeerEgressSocketBinding.WindowsForwardRow(row.path("interfaceIndex").asLong(),
                        row.path("prefix").asText(), row.path("nextHop").asText(), row.path("metric").asLong()));
            }
            assertEquals(expected, rows, "forward " + name);
            forwardByName.put(name, rows);
        }
        Map<String, List<PeerEgressSocketBinding.WindowsInterfaceRow>> interfacesByName = new HashMap<>();
        for (JsonNode table : windows.path("interfaceTables")) {
            String name = table.path("name").asText();
            var rows = PeerEgressSocketBinding.parseWindowsInterfaceTable(
                    HexFormat.of().parseHex(table.path("hex").asText()));
            assertEquals(table.path("expect").path("parsed").asBoolean(), rows != null, "interfaces " + name);
            if (rows == null) {
                continue;
            }
            List<PeerEgressSocketBinding.WindowsInterfaceRow> expected = new ArrayList<>();
            for (JsonNode row : table.path("expect").path("rows")) {
                expected.add(new PeerEgressSocketBinding.WindowsInterfaceRow(row.path("interfaceIndex").asLong(),
                        row.path("metric").asLong(), row.path("connected").asBoolean(),
                        row.path("disableDefaultRoutes").asBoolean()));
            }
            assertEquals(expected, rows, "interfaces " + name);
            interfacesByName.put(name, rows);
        }

        JsonNode joined = windows.path("routes");
        var forward = forwardByName.get(joined.path("forward").asText());
        var interfaces = interfacesByName.get(joined.path("interfaces").asText());
        assertNotNull(forward);
        assertNotNull(interfaces);
        var routes = PeerEgressSocketBinding.windowsRoutes(forward, interfaces);
        assertEquals(routes(joined.path("expect")), routes, "joined routes");
        for (JsonNode testCase : windows.path("cases")) {
            assertChoice("windows " + testCase.path("name").asText(), routes, testCase);
        }
    }

    @Test
    void macosTablesMatchTheSharedVector() throws IOException {
        JsonNode macos = vector().path("macos");
        Map<String, List<PeerEgressSocketBinding.Route>> byTable = new HashMap<>();
        for (JsonNode entry : macos.path("routes")) {
            String table = entry.path("table").asText();
            var routes = PeerEgressSocketBinding.macosRoutes(macos.path("tables").path(table).asText());
            assertEquals(routes(entry.path("expect")), routes, "macos routes " + table);
            byTable.put(table, routes);
        }
        for (JsonNode testCase : macos.path("cases")) {
            assertChoice("macos " + testCase.path("name").asText(),
                    byTable.get(testCase.path("table").asText()), testCase);
        }
    }

    @Test
    void linuxTablesMatchTheSharedVector() throws IOException {
        JsonNode linux = vector().path("linux");
        assertTrue(linux.path("routes").size() > 0, "no Linux tables");
        for (JsonNode entry : linux.path("routes")) {
            String table = entry.path("table").asText();
            assertEquals(routes(entry.path("expect")),
                    PeerEgressRouteCommands.parseRouteTable(linux.path("tables").path(table).asText()),
                    "linux routes " + table);
        }
        // The captures that justify reading the table at all: `ip route get` answering with the tunnel.
        linux.path("captures").fields().forEachRemaining(capture -> {
            if (capture.getKey().startsWith("get-covered")) {
                PeerEgressRouteCommands.Hop hop =
                        PeerEgressRouteCommands.parseRouteGet(capture.getValue().path("stdout").asText());
                assertTrue(PeerEgressRouteCommands.hopIsDevice(hop, "specus0"),
                        capture.getKey() + " parsed as " + hop);
            }
        });
    }

    @Test
    void bypassHopsMatchTheSharedVector() throws IOException {
        JsonNode root = vector();
        Map<String, Map<String, List<PeerEgressSocketBinding.Route>>> tables = new HashMap<>();
        tables.put("linux", new HashMap<>());
        tables.put("macos", new HashMap<>());
        tables.put("windows", new HashMap<>());
        root.path("linux").path("tables").fields().forEachRemaining(table -> tables.get("linux")
                .put(table.getKey(), PeerEgressRouteCommands.parseRouteTable(table.getValue().asText())));
        root.path("macos").path("tables").fields().forEachRemaining(table -> tables.get("macos")
                .put(table.getKey(), PeerEgressSocketBinding.macosRoutes(table.getValue().asText())));
        JsonNode windows = root.path("windows");
        List<PeerEgressSocketBinding.WindowsForwardRow> forward = null;
        List<PeerEgressSocketBinding.WindowsInterfaceRow> interfaces = null;
        for (JsonNode table : windows.path("forwardTables")) {
            if (table.path("name").asText().equals(windows.path("routes").path("forward").asText())) {
                forward = PeerEgressSocketBinding.parseWindowsForwardTable(
                        HexFormat.of().parseHex(table.path("hex").asText()));
            }
        }
        for (JsonNode table : windows.path("interfaceTables")) {
            if (table.path("name").asText().equals(windows.path("routes").path("interfaces").asText())) {
                interfaces = PeerEgressSocketBinding.parseWindowsInterfaceTable(
                        HexFormat.of().parseHex(table.path("hex").asText()));
            }
        }
        assertNotNull(forward);
        assertNotNull(interfaces);
        tables.get("windows").put("typical", PeerEgressSocketBinding.windowsRoutes(forward, interfaces));

        JsonNode cases = root.path("hops").path("cases");
        assertTrue(cases.size() > 0, "no hop cases");
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            String platform = testCase.path("platform").asText();
            List<PeerEgressSocketBinding.Route> routes = "inline".equals(platform)
                    ? routes(testCase.path("routes"))
                    : tables.get(platform).get(testCase.path("table").asText());
            List<String> owned = new ArrayList<>();
            testCase.path("owned").forEach(prefix -> owned.add(prefix.asText()));
            PeerEgressSocketBinding.Route hop = PeerEgressSocketBinding.selectBypassHop(routes,
                    testCase.path("tunnel").asText(), owned, testCase.path("destination").asText());
            JsonNode expected = testCase.path("expect").path("hop");
            if (expected.isNull()) {
                assertNull(hop, name + ": want no hop");
            } else {
                assertNotNull(hop, name + ": no hop");
                assertEquals(expected.path("interface").asText(), hop.iface(), name + " interface");
                assertEquals(expected.path("gateway").asText(), hop.gateway(), name + " gateway");
            }
        }
    }

    /**
     * The fallback a commander takes when its query answers with the tunnel: the table with the
     * tunnel left out, and a refusal that says why when nothing else leads there.
     */
    /** Every sampled table in the vector, as this runtime parses it. */
    private static Map<String, Map<String, List<PeerEgressSocketBinding.Route>>> tables(JsonNode root) {
        Map<String, Map<String, List<PeerEgressSocketBinding.Route>>> tables = new HashMap<>();
        tables.put("linux", new HashMap<>());
        tables.put("macos", new HashMap<>());
        tables.put("windows", new HashMap<>());
        root.path("linux").path("tables").fields().forEachRemaining(table -> tables.get("linux")
                .put(table.getKey(), PeerEgressRouteCommands.parseRouteTable(table.getValue().asText())));
        root.path("macos").path("tables").fields().forEachRemaining(table -> tables.get("macos")
                .put(table.getKey(), PeerEgressSocketBinding.macosRoutes(table.getValue().asText())));
        JsonNode windows = root.path("windows");
        List<PeerEgressSocketBinding.WindowsForwardRow> forward = null;
        List<PeerEgressSocketBinding.WindowsInterfaceRow> interfaces = null;
        for (JsonNode table : windows.path("forwardTables")) {
            if (table.path("name").asText().equals(windows.path("routes").path("forward").asText())) {
                forward = PeerEgressSocketBinding.parseWindowsForwardTable(
                        HexFormat.of().parseHex(table.path("hex").asText()));
            }
        }
        for (JsonNode table : windows.path("interfaceTables")) {
            if (table.path("name").asText().equals(windows.path("routes").path("interfaces").asText())) {
                interfaces = PeerEgressSocketBinding.parseWindowsInterfaceTable(
                        HexFormat.of().parseHex(table.path("hex").asText()));
            }
        }
        assertNotNull(forward);
        assertNotNull(interfaces);
        tables.get("windows").put("typical", PeerEgressSocketBinding.windowsRoutes(forward, interfaces));
        return tables;
    }

    /**
     * What the consumer's own routes look like after a network change, and the repair each needs.
     * The policy -- a tunnel route on another interface is a conflict, a bypass follows the hop the
     * table would choose with the owned prefixes left out -- has to be the same in three runtimes.
     */
    @Test
    void driftMatchesTheSharedVector() throws IOException {
        JsonNode root = vector();
        Map<String, Map<String, List<PeerEgressSocketBinding.Route>>> tables = tables(root);
        JsonNode cases = root.path("drift").path("cases");
        assertTrue(cases.size() > 0, "no drift cases");
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            String platform = testCase.path("platform").asText();
            List<PeerEgressSocketBinding.Route> routes = "inline".equals(platform)
                    ? routes(testCase.path("routes"))
                    : tables.get(platform).get(testCase.path("table").asText());
            List<PeerEgressRoutePlanner.Route> owned = new ArrayList<>();
            for (JsonNode entry : testCase.path("owned")) {
                owned.add(new PeerEgressRoutePlanner.Route(entry.path("cidr").asText(),
                        PeerEgressRoutePlanner.Kind.fromWireName(entry.path("kind").asText()), ""));
            }
            List<PeerEgressSocketBinding.Drift> found =
                    PeerEgressSocketBinding.drifts(owned, routes, testCase.path("tunnel").asText());
            JsonNode expect = testCase.path("expect");
            assertEquals(expect.size(), found.size(), name + ": found " + found);
            for (int index = 0; index < expect.size(); index++) {
                JsonNode want = expect.get(index);
                PeerEgressSocketBinding.Drift got = found.get(index);
                assertEquals(want.path("cidr").asText(), got.route().cidr(), name + ": drift " + index);
                assertEquals(want.path("reason").asText(), got.reason(), name + ": drift " + index + " reason");
                assertEquals(want.path("action").asText(), got.action(), name + ": drift " + index + " action");
            }
        }
    }

    @Test
    void theHopFromTheTableLeavesTheTunnelOut() throws IOException {
        List<PeerEgressSocketBinding.Route> routes = PeerEgressRouteCommands.parseRouteTable(
                vector().path("linux").path("tables").path("show-rich").asText());

        PeerEgressSocketBinding.Route hop =
                PeerEgressSocketBinding.bypassHopFromTable("203.0.113.9", "specus0", () -> routes);
        assertEquals("eth0", hop.iface());
        assertEquals("192.168.64.1", hop.gateway());
        assertThrows(PeerEgressSocketBinder.NoPhysicalRouteException.class,
                () -> PeerEgressSocketBinding.bypassHopFromTable("192.0.2.9", "specus0", () -> routes));
        IOException unreadable = assertThrows(IOException.class,
                () -> PeerEgressSocketBinding.bypassHopFromTable("203.0.113.9", "specus0", () -> {
                    throw new IOException("ip: not found");
                }));
        assertTrue(unreadable.getMessage().contains("ip: not found"), unreadable.getMessage());
    }

    @Test
    void socketOptionsMatchTheSharedVector() throws IOException {
        JsonNode options = vector().path("socketOptions");
        assertEquals(PeerEgressSocketBinding.WINDOWS_IP_UNICAST_IF, options.path("windows").path("name").asInt());
        assertEquals(PeerEgressSocketBinding.MACOS_IP_BOUND_IF, options.path("macos").path("name").asInt());
        assertEquals(PeerEgressSocketBinding.IPPROTO_IP, options.path("windows").path("level").asInt());
        assertEquals(PeerEgressSocketBinding.IPPROTO_IP, options.path("macos").path("level").asInt());
        for (JsonNode testCase : options.path("windows").path("cases")) {
            assertEquals(testCase.path("hex").asText(), HexFormat.of().formatHex(
                    PeerEgressSocketBinding.windowsUnicastInterfaceOption(testCase.path("index").asLong())),
                    "IP_UNICAST_IF " + testCase.path("index").asLong());
        }
        for (JsonNode testCase : options.path("macos").path("cases")) {
            assertEquals(testCase.path("hex").asText(), HexFormat.of().formatHex(
                    PeerEgressSocketBinding.macosBoundInterfaceOption(testCase.path("index").asLong())),
                    "IP_BOUND_IF " + testCase.path("index").asLong());
        }
    }
}
