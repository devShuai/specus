package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The pure half of the system DNS takeover, bound to every section of
 * {@code protocol/test-vectors/peer-egress-dns-takeover-v1.json}: reading each platform's tools,
 * deciding, the exact commands, and giving back over someone else's change.
 */
class PeerEgressDnsTakeoverVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve("peer-egress-dns-takeover-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-dns-takeover-v1.json");
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(item -> out.add(item.asText()));
        return out;
    }

    private static void nonEmpty(JsonNode section, String name) {
        assertTrue(section.isArray() && !section.isEmpty(), name + " carried no cases");
    }

    @Test
    void constantsMatch() throws IOException {
        JsonNode document = vector();
        String listen = document.path("listen").asText();
        assertEquals(document.path("nrptComment").asText(), PeerEgressDnsTakeoverParse.NRPT_COMMENT);
        assertEquals(document.path("resolvConfWritten").asText(), PeerEgressDnsTakeoverParse.resolvConfWritten(listen));
        assertEquals(strings(document.path("resolvedStubs")), PeerEgressDnsTakeoverParse.RESOLVED_STUBS);
        assertEquals(document.path("windowsReadServers").asText(), PeerEgressDnsTakeoverParse.WINDOWS_READ_SERVERS);
        assertEquals(document.path("windowsReadNrpt").asText(), PeerEgressDnsTakeoverParse.WINDOWS_READ_NRPT);
    }

    @Test
    void readsEachPlatform() throws IOException {
        JsonNode document = vector();
        nonEmpty(document.path("parseResolvectl"), "parseResolvectl");
        for (JsonNode testCase : document.path("parseResolvectl")) {
            assertEquals(strings(testCase.path("servers")), PeerEgressDnsTakeoverParse.parseResolvectl(
                    testCase.path("output").asText(), testCase.path("tunnel").asText()), testCase.path("name").asText());
        }
        nonEmpty(document.path("parseResolvConf"), "parseResolvConf");
        for (JsonNode testCase : document.path("parseResolvConf")) {
            assertEquals(strings(testCase.path("servers")),
                    PeerEgressDnsTakeoverParse.parseResolvConf(testCase.path("text").asText()), testCase.path("name").asText());
        }
        JsonNode services = document.path("parseMacServices");
        assertEquals(strings(services.path("services")),
                PeerEgressDnsTakeoverParse.parseMacServices(services.path("output").asText()));
        nonEmpty(document.path("parseMacDnsServers"), "parseMacDnsServers");
        for (JsonNode testCase : document.path("parseMacDnsServers")) {
            assertEquals(strings(testCase.path("servers")),
                    PeerEgressDnsTakeoverParse.parseMacDnsServers(testCase.path("output").asText()), testCase.path("name").asText());
        }
        nonEmpty(document.path("parseScutil"), "parseScutil");
        for (JsonNode testCase : document.path("parseScutil")) {
            assertEquals(strings(testCase.path("servers")),
                    PeerEgressDnsTakeoverParse.parseScutil(testCase.path("output").asText()), testCase.path("name").asText());
        }
        nonEmpty(document.path("parseWindowsServers"), "parseWindowsServers");
        for (JsonNode testCase : document.path("parseWindowsServers")) {
            assertEquals(strings(testCase.path("servers")), PeerEgressDnsTakeoverParse.parseWindowsServers(
                    testCase.path("json").asText(), testCase.path("tunnelIndex").asLong()), testCase.path("name").asText());
        }
        nonEmpty(document.path("parseWindowsNrpt"), "parseWindowsNrpt");
        for (JsonNode testCase : document.path("parseWindowsNrpt")) {
            assertEquals(testCase.path("foreignRoot").asBoolean(),
                    PeerEgressDnsTakeoverParse.parseWindowsNrpt(testCase.path("json").asText()), testCase.path("name").asText());
        }
    }

    @Test
    void decides() throws IOException {
        JsonNode document = vector();
        nonEmpty(document.path("linuxMode"), "linuxMode");
        for (JsonNode testCase : document.path("linuxMode")) {
            PeerEgressDnsTakeoverParse.LinuxMode mode = PeerEgressDnsTakeoverParse.linuxMode(
                    testCase.path("resolvectlOk").asBoolean(), strings(testCase.path("resolvConfServers")),
                    testCase.path("resolvConfIsSymlink").asBoolean());
            String name = testCase.path("name").asText();
            assertEquals(testCase.path("mode").isNull() ? null : testCase.path("mode").asText(), mode.mode(), name);
            assertEquals(testCase.path("reason").isNull() ? null : testCase.path("reason").asText(), mode.reason(), name);
        }
        nonEmpty(document.path("upstreams"), "upstreams");
        for (JsonNode testCase : document.path("upstreams")) {
            String name = testCase.path("name").asText();
            PeerEgressDnsTakeoverParse.Upstreams upstreams = PeerEgressDnsTakeoverParse.classifyUpstreams(
                    strings(testCase.path("servers")), strings(testCase.path("virtualAddresses")),
                    document.path("fakeIpCidr").asText(), document.path("meshCidr").asText());
            if (testCase.path("code").isNull()) {
                assertNull(upstreams.code(), name);
                assertEquals(strings(testCase.path("upstreams")), upstreams.upstreams(), name);
            } else {
                assertEquals(testCase.path("code").asText(), upstreams.code(), name);
                assertEquals(testCase.path("reason").asText(), upstreams.reason(), name);
            }
        }
    }

    /** A plan's steps as the vector writes them: command lines as arrays, the rest as objects. */
    private static ArrayNode render(List<PeerEgressDnsTakeoverParse.Step> steps) {
        ArrayNode out = MAPPER.createArrayNode();
        for (PeerEgressDnsTakeoverParse.Step step : steps) {
            if (step.argv() != null) {
                ArrayNode argv = out.addArray();
                step.argv().forEach(argv::add);
            } else {
                ObjectNode object = out.addObject();
                if (step.write() != null) {
                    object.put("write", step.write());
                    object.put("content", step.content());
                } else if (step.restore() != null) {
                    object.put("restore", step.restore());
                } else {
                    object.put("restore-service", step.restoreService());
                }
            }
        }
        return out;
    }

    @Test
    void plansTheExactCommands() throws IOException {
        JsonNode document = vector();
        nonEmpty(document.path("plan"), "plan");
        for (JsonNode testCase : document.path("plan")) {
            String platform = testCase.path("platform").asText();
            PeerEgressDnsTakeoverParse.Plan plan = PeerEgressDnsTakeoverParse.plan(platform,
                    testCase.path("listen").asText(), testCase.path("tunnel").asText("specus0"),
                    strings(testCase.path("services")));
            assertEquals(testCase.path("apply"), render(plan.apply()), platform + " apply");
            assertEquals(testCase.path("revert"), render(plan.revert()), platform + " revert");
        }
        assertNull(PeerEgressDnsTakeoverParse.plan("plan9", "198.18.0.1", "specus0", List.of()));
    }

    @Test
    void givesBackOverSomeoneElsesChange() throws IOException {
        JsonNode document = vector();
        String listen = document.path("listen").asText();
        nonEmpty(document.path("revertResolvConf"), "revertResolvConf");
        for (JsonNode testCase : document.path("revertResolvConf")) {
            String name = testCase.path("name").asText();
            PeerEgressDnsTakeoverParse.Revert revert = PeerEgressDnsTakeoverParse.revertResolvConf(
                    testCase.path("current").asText(), testCase.path("original").asText(), listen);
            assertEquals(testCase.path("action").asText(), revert.action(), name);
            assertEquals(testCase.path("content").isMissingNode() ? null : testCase.path("content").asText(), revert.content(), name);
            assertEquals(testCase.path("warning").isMissingNode() ? null : testCase.path("warning").asText(), revert.warning(), name);
        }
        nonEmpty(document.path("revertMacService"), "revertMacService");
        for (JsonNode testCase : document.path("revertMacService")) {
            String name = testCase.path("name").asText();
            PeerEgressDnsTakeoverParse.Revert revert = PeerEgressDnsTakeoverParse.revertMacService(
                    testCase.path("service").asText(), strings(testCase.path("current")),
                    strings(testCase.path("original")), listen);
            assertEquals(testCase.path("action").asText(), revert.action(), name);
            assertEquals(testCase.path("command").isMissingNode() ? null : strings(testCase.path("command")),
                    revert.command(), name);
            assertEquals(testCase.path("warning").isMissingNode() ? null : testCase.path("warning").asText(), revert.warning(), name);
        }
    }

    /** Which interfaces are tunnels on each platform, the client's own excluded. */
    @Test
    void findsTunnelInterfaces() throws IOException {
        List<PeerEgressDnsTakeoverParse.LocalInterface> linux = List.of(
                new PeerEgressDnsTakeoverParse.LocalInterface("eth0", 2, false, -1, List.of("192.168.1.5")),
                new PeerEgressDnsTakeoverParse.LocalInterface("wg0", 3, true, -1, List.of("10.8.0.2")),
                new PeerEgressDnsTakeoverParse.LocalInterface("specus0", 4, true, -1, List.of("100.96.0.1")));
        assertEquals(List.of("10.8.0.2"), PeerEgressDnsTakeoverParse.tunnelAddresses("linux", linux, "specus0", 0));
        List<PeerEgressDnsTakeoverParse.LocalInterface> mac = List.of(
                new PeerEgressDnsTakeoverParse.LocalInterface("en0", 6, false, -1, List.of("192.168.1.5")),
                new PeerEgressDnsTakeoverParse.LocalInterface("utun4", 20, true, -1, List.of("10.9.0.2")),
                new PeerEgressDnsTakeoverParse.LocalInterface("ppp0", 21, true, -1, List.of("10.10.0.2")),
                new PeerEgressDnsTakeoverParse.LocalInterface("utun3", 19, true, -1, List.of("100.96.0.1")));
        assertEquals(List.of("10.9.0.2", "10.10.0.2"), PeerEgressDnsTakeoverParse.tunnelAddresses("macos", mac, "utun3", 0));
        List<PeerEgressDnsTakeoverParse.LocalInterface> windows = PeerEgressDnsTakeoverParse.parseWindowsInterfaces(
                "[{\"InterfaceIndex\":12,\"InterfaceType\":6,\"IPAddress\":\"192.168.1.5\"},"
                        + "{\"InterfaceIndex\":17,\"InterfaceType\":53,\"IPAddress\":\"100.96.0.1\"},"
                        + "{\"InterfaceIndex\":22,\"InterfaceType\":53,\"IPAddress\":\"10.8.0.2\"},"
                        + "{\"InterfaceIndex\":23,\"InterfaceType\":131,\"IPAddress\":\"10.11.0.2\"},"
                        + "{\"InterfaceIndex\":24,\"InterfaceType\":null,\"IPAddress\":\"10.12.0.2\"}]");
        assertEquals(List.of("10.8.0.2", "10.11.0.2"), PeerEgressDnsTakeoverParse.tunnelAddresses("windows", windows, "specus", 17));
        assertTrue(PeerEgressDnsTakeoverParse.tunnelAddresses("plan9", linux, "specus0", 0).isEmpty());
    }

    /** Address literals are read without ever asking a resolver. */
    @Test
    void readsAddressLiteralsWithoutResolving() {
        for (String literal : List.of("::1", "fe80::1", "2001:db8::53", "::ffff:192.0.2.1", "1:2:3:4:5:6:7:8", "::")) {
            assertTrue(PeerEgressDnsTakeoverParse.isAddressLiteral(literal), literal);
        }
        for (String text : List.of("Error: no servers", "1:2", "12345::", "1::2::3", "a:b:c:d:e:f:1:2:3", "dns.example",
                "There aren't any DNS Servers set on Wi-Fi.")) {
            assertFalse(PeerEgressDnsTakeoverParse.isAddressLiteral(text), text);
        }
    }
}
