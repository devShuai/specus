package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import com.theshuai.specusclient.cli.EgressView;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An online egress the catalogue does not offer, or whose client cannot carry peer egress, beyond
 * the per-packet decisions the shared vector pins (protocol/spec/peer-egress.md, "能力不支持"): the
 * flows such an egress was carrying are closed when its standing turns, a new control session
 * forgets that a catalogue came, the status says what the catalogue said and when the wait for one
 * is over, and a person is shown the pinned lines.
 */
class PeerEgressStandingTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long EPOCH = 1_800_000_000_000L;
    private static final String VIRTUAL_IP = "100.96.0.7";

    @TempDir
    Path directory;

    private final List<long[]> sentTo = new ArrayList<>();
    private final List<byte[]> sentFrames = new ArrayList<>();
    private final List<byte[]> written = new ArrayList<>();
    private final Map<Long, Boolean> available = new HashMap<>();
    private PeerEgressMesh mesh;

    private final class Host implements PeerEgressMesh.Host {
        @Override
        public boolean sendToPeer(long peerId, byte[] frame) {
            synchronized (PeerEgressStandingTests.this) {
                sentTo.add(new long[] {peerId});
                sentFrames.add(frame.clone());
            }
            return true;
        }

        @Override
        public void writeToDevice(byte[] packet) {
            synchronized (PeerEgressStandingTests.this) {
                written.add(packet.clone());
            }
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
            return VIRTUAL_IP;
        }

        @Override
        public List<String> deploymentDenyCidrs() {
            return List.of();
        }

        @Override
        public List<String> peerEndpointAddresses() {
            return List.of();
        }

        @Override
        public Integer pathMtuForPeer(long peerId) {
            return null;
        }

        @Override
        public Path routeJournalPath() {
            return directory.resolve("egress-routes.json");
        }

        @Override
        public Map<Long, Boolean> egressAvailability() {
            return Map.copyOf(available);
        }

        @Override
        public Map<Long, String> egressPaths() {
            Map<Long, String> paths = new HashMap<>();
            available.forEach((egress, up) -> {
                if (up) {
                    paths.put(egress, PeerEgressStatus.PATH_DIRECT);
                }
            });
            return paths;
        }
    }

    /** A routing table that takes everything and holds nothing. */
    private static final class Commander implements PeerEgressRouteInstaller.Commander {
        @Override
        public PeerEgressRouteInstaller.Conflict conflict(PeerEgressRoutePlanner.Route route) {
            return PeerEgressRouteInstaller.Conflict.none();
        }

        @Override
        public void install(PeerEgressRoutePlanner.Route route) {
        }

        @Override
        public void remove(PeerEgressRoutePlanner.Route route) {
        }
    }

    @AfterEach
    void stop() {
        if (mesh != null) {
            mesh.close();
        }
    }

    private PeerEgressMesh newMesh() {
        mesh = new PeerEgressMesh(new Host(), (protocol, host, port, timeoutMs) -> {
            throw new IOException("nothing is dialled in this test");
        }, new Commander());
        return mesh;
    }

    private static PeerEgressRule rule(String match, long egress) {
        PeerEgressRule value = new PeerEgressRule();
        value.setMatch(match);
        value.setAction(PeerEgressRule.ACTION_EGRESS);
        value.setEgressClientId(egress);
        return value;
    }

    private static int address(String dotted) {
        return Objects.requireNonNull(Ipv4Cidr.parseAddress(dotted), dotted);
    }

    private static byte[] segment(String source, String destination, int sourcePort, int seq, int ack, int flags,
            String payload) {
        return PeerEgressSegment.build(new PeerEgressSegment.Segment(address(source), address(destination),
                sourcePort, 443, seq, ack, flags, 65535, 0, payload.getBytes(StandardCharsets.US_ASCII)));
    }

    private static byte[] syn(String destination, int sourcePort) {
        return segment(VIRTUAL_IP, destination, sourcePort, 1000, 0, PeerEgressSegment.FLAG_SYN, "");
    }

    /** The application's next segment on an open connection, which tells the consumer where to reset it. */
    private static byte[] data(String destination, int sourcePort) {
        return segment(VIRTUAL_IP, destination, sourcePort, 1001, 700001, PeerEgressSegment.FLAG_ACK, "GET / ");
    }

    private static String catalogue(long revision, String entries) {
        return "{\"type\":\"egress-catalog\",\"revision\":" + revision + ",\"egresses\":[" + entries + "]}";
    }

    private static PeerEgressCatalog.Snapshot snapshot(String entries) {
        PeerEgressCatalog catalog = new PeerEgressCatalog();
        catalog.newSession(EPOCH);
        assertTrue(catalog.read(catalogue(1, entries)), entries);
        return catalog.snapshot();
    }

    private JsonNode consumerStatus() {
        return MAPPER.valueToTree(mesh.status()).path("consumer");
    }

    private JsonNode peer(JsonNode consumer, long id) {
        for (JsonNode peer : consumer.path("peers")) {
            if (peer.path("clientId").asLong() == id) {
                return peer;
            }
        }
        throw new AssertionError("no peer " + id + " in " + consumer.path("peers"));
    }

    private static Map<String, Long> counts(JsonNode object) {
        Map<String, Long> counts = new java.util.TreeMap<>();
        object.fields().forEachRemaining(field -> counts.put(field.getKey(), field.getValue().asLong()));
        return counts;
    }

    private synchronized List<PeerEgressFrame.Control> purgesTo(long egress) {
        List<PeerEgressFrame.Control> purges = new ArrayList<>();
        for (int index = 0; index < sentFrames.size(); index++) {
            PeerEgressFrame.Decoded decoded = PeerEgressFrame.parse(sentFrames.get(index));
            if (sentTo.get(index)[0] != egress || !decoded.accepted() || decoded.type() != PeerEgressFrame.TYPE_CONTROL) {
                continue;
            }
            PeerEgressFrame.Control control = PeerEgressFrame.decodeControl(decoded.body());
            if (control != null && PeerEgressFrame.CONTROL_FLOW_PURGE.equals(control.type())) {
                purges.add(control);
            }
        }
        return purges;
    }

    private synchronized void clearSent() {
        sentTo.clear();
        sentFrames.clear();
        written.clear();
    }

    /**
     * A standing that turns into one that blocks closes the egress's flows the way going offline
     * does: the application is reset where its stack accepts it, and the egress is told to close its
     * side. Not offered and unsupported both; a standing that stops blocking closes nothing.
     */
    @Test
    void aStandingThatTurnsBlockingClosesItsFlowsLikeGoingOffline() {
        for (String turned : List.of("{\"clientId\":9,\"egressVersion\":1}", "{\"clientId\":2,\"egressVersion\":0}")) {
            List<byte[]> toTun = new ArrayList<>();
            PeerEgressConsumer consumer = new PeerEgressConsumer((egress, frame) -> true, toTun::add);
            consumer.configure(List.of(rule("203.0.113.0/24", 2L)), PeerEgressRules.DEFAULT_MESH_CIDR, VIRTUAL_IP, EPOCH);
            consumer.setEgressOnline(2L, true, EPOCH);
            assertTrue(consumer.setCatalog(snapshot("{\"clientId\":2,\"egressVersion\":1}"), EPOCH).isEmpty());
            assertEquals(PeerEgressConsumer.Outcome.FORWARDED, consumer.handleOutbound(syn("203.0.113.10", 40000), EPOCH));
            assertEquals(PeerEgressConsumer.Outcome.FORWARDED, consumer.handleOutbound(data("203.0.113.10", 40000), EPOCH));
            assertTrue(toTun.isEmpty());

            Map<Long, List<String>> purge = consumer.setCatalog(snapshot(turned), EPOCH + 1);

            assertEquals(Map.of(2L, List.of("203.0.113.10/32")), purge, turned);
            assertEquals(0, consumer.flowCount(), turned + ": the flow outlived its standing");
            assertEquals(1, toTun.size(), turned + ": want the reset");
            PeerEgressSegment.Segment reset = PeerEgressSegment.parse(toTun.get(0));
            assertNotNull(reset, turned);
            assertEquals(PeerEgressSegment.FLAG_RST | PeerEgressSegment.FLAG_ACK, reset.flags(), turned);
            assertEquals(700001, reset.seq(), turned);
            assertEquals(1007, reset.ack(), turned);
        }

        // Unknown blocks nothing: a new session's empty view leaves a flow to an offered egress be.
        PeerEgressConsumer consumer = new PeerEgressConsumer((egress, frame) -> true, packet -> { });
        consumer.configure(List.of(rule("203.0.113.0/24", 2L)), PeerEgressRules.DEFAULT_MESH_CIDR, VIRTUAL_IP, EPOCH);
        consumer.setEgressOnline(2L, true, EPOCH);
        consumer.setCatalog(snapshot("{\"clientId\":2,\"egressVersion\":1}"), EPOCH);
        consumer.handleOutbound(syn("203.0.113.10", 40000), EPOCH);
        assertTrue(consumer.setCatalog(PeerEgressCatalog.Snapshot.empty(), EPOCH + 1).isEmpty());
        assertEquals(1, consumer.flowCount());
    }

    /** A flow to a fake address is closed the same way when its egress stops being offered. */
    @Test
    void aDomainFlowIsClosedWhenItsEgressStopsBeingOffered() {
        PeerEgressConsumer consumer = new PeerEgressConsumer((egress, frame) -> true, packet -> { });
        PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse("198.18.0.0/24"), () -> EPOCH);
        consumer.configure(List.of(rule("example.com", 2L)), PeerEgressRules.DEFAULT_MESH_CIDR, VIRTUAL_IP, pool, EPOCH);
        consumer.setEgressOnline(2L, true, EPOCH);
        consumer.setCatalog(snapshot("{\"clientId\":2,\"egressVersion\":1,\"domainTargetCapable\":true}"), EPOCH);
        String fake = pool.query("example.com", EPOCH).addressText();
        assertEquals(PeerEgressConsumer.Outcome.FORWARDED, consumer.handleOutbound(syn(fake, 40000), EPOCH));

        Map<Long, List<String>> purge = consumer.setCatalog(
                snapshot("{\"clientId\":2,\"egressVersion\":0,\"domainTargetCapable\":true}"), EPOCH + 1);

        assertEquals(Map.of(2L, List.of(fake + "/32")), purge);
        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS, consumer.handleOutbound(syn(fake, 40001), EPOCH + 2));
        assertEquals(Map.of("egress-unsupported", 1L), consumer.blockedCounts());
    }

    /** Through the mesh: a pushed catalogue that turns the standing reaches the egress as a flow-purge. */
    @Test
    void theEgressIsToldToCloseWhenThePushedCatalogueTurnsItsStanding() {
        available.put(2L, true);
        newMesh().applyRules(List.of(rule("203.0.113.0/24", 2L)));
        mesh.newControlSession();
        mesh.applyEgressCatalog(catalogue(1, "{\"clientId\":2,\"egressVersion\":1}"));
        assertTrue(mesh.handleOutbound(syn("203.0.113.10", 40000)));
        assertTrue(mesh.handleOutbound(data("203.0.113.10", 40000)));
        clearSent();

        mesh.applyEgressCatalog(catalogue(2, "{\"clientId\":2,\"egressVersion\":0}"));

        List<PeerEgressFrame.Control> purges = purgesTo(2L);
        assertEquals(1, purges.size(), "want one flow-purge to egress 2");
        assertEquals(List.of("203.0.113.10/32"), purges.get(0).destinations());
        assertEquals(1, written.size(), "the application's connection was not reset");
    }

    /**
     * {@code consumer.catalog} waits 30 seconds after control authentication, says none after that
     * with no catalogue, received once one came; a new control session waits again. Before any
     * control session it waits.
     */
    @Test
    void theCatalogueWaitsThenSaysNoneUntilOneIsReceived() throws IOException {
        long wait = PeerEgressStandingVectorTests.vector().path("catalogWaitSeconds").asLong() * 1000L;
        long[] now = {EPOCH};
        available.put(2L, true);
        newMesh().catalogClock = () -> now[0];
        mesh.applyRules(List.of(rule("203.0.113.0/24", 2L)));

        assertEquals("waiting", consumerStatus().path("catalog").asText(), "before any control session");
        now[0] += 10 * wait;
        assertEquals("waiting", consumerStatus().path("catalog").asText(), "still no control session");

        mesh.newControlSession();
        long login = now[0];
        now[0] = login + wait - 1;
        assertEquals("waiting", consumerStatus().path("catalog").asText());
        now[0] = login + wait;
        assertEquals("none", consumerStatus().path("catalog").asText());
        assertEquals("unknown", peer(consumerStatus(), 2L).path("standing").asText());

        mesh.applyEgressCatalog(catalogue(1, "{\"clientId\":2,\"egressVersion\":1}"));
        assertEquals("received", consumerStatus().path("catalog").asText());
        assertEquals("offered", peer(consumerStatus(), 2L).path("standing").asText());

        now[0] += 5;
        mesh.newControlSession();
        assertEquals("waiting", consumerStatus().path("catalog").asText(), "a new session has received nothing");
        assertEquals("unknown", peer(consumerStatus(), 2L).path("standing").asText());
        now[0] += wait;
        assertEquals("none", consumerStatus().path("catalog").asText());
        // The new session's server numbers from 1 again.
        mesh.applyEgressCatalog(catalogue(1, "{\"clientId\":2,\"egressVersion\":1}"));
        assertEquals("received", consumerStatus().path("catalog").asText());
    }

    /**
     * The status names each egress's standing, online or not, and counts the two new reasons by
     * name. Driven with real packets through the mesh, so the counts are the consumer's own.
     */
    @Test
    void theStatusSaysWhatTheCatalogueSaidAndCountsWhatItBlocked() {
        available.putAll(Map.of(42L, true, 43L, true, 44L, true, 45L, false));
        newMesh().applyRules(List.of(rule("203.0.113.0/24", 42L), rule("198.51.100.0/24", 43L),
                rule("192.0.2.0/24", 44L), rule("10.20.0.0/16", 45L)));
        mesh.newControlSession();

        // No catalogue yet: every egress unknown, and an online one is sent to.
        JsonNode consumer = consumerStatus();
        assertEquals("waiting", consumer.path("catalog").asText());
        for (long id : List.of(42L, 43L, 44L, 45L)) {
            assertEquals("unknown", peer(consumer, id).path("standing").asText(), "egress " + id);
        }
        assertTrue(mesh.handleOutbound(syn("203.0.113.10", 40000)));
        assertTrue(consumerStatus().path("blocked").isEmpty(), consumerStatus().path("blocked").toString());

        mesh.applyEgressCatalog(catalogue(1, "{\"clientId\":43,\"egressVersion\":0},"
                + "{\"clientId\":44,\"egressVersion\":1},{\"clientId\":45,\"egressVersion\":1}"));
        consumer = consumerStatus();
        assertEquals("received", consumer.path("catalog").asText());
        assertEquals("not-offered", peer(consumer, 42L).path("standing").asText());
        assertEquals("unsupported", peer(consumer, 43L).path("standing").asText());
        assertEquals("offered", peer(consumer, 44L).path("standing").asText());
        assertEquals("offered", peer(consumer, 45L).path("standing").asText());
        assertFalse(peer(consumer, 45L).path("online").asBoolean());
        // The key order the spec's example has: clientId, online, standing, path, flows.
        List<String> keys = new ArrayList<>();
        peer(consumer, 44L).fieldNames().forEachRemaining(keys::add);
        assertEquals(List.of("clientId", "online", "standing", "path", "flows"), keys);

        clearSent();
        assertTrue(mesh.handleOutbound(syn("203.0.113.11", 40001)));
        assertTrue(mesh.handleOutbound(syn("198.51.100.10", 40002)));
        assertTrue(mesh.handleOutbound(syn("192.0.2.10", 40003)));
        assertTrue(mesh.handleOutbound(syn("10.20.0.10", 40004)));
        assertEquals(Map.of("egress-not-offered", 1L, "egress-unsupported", 1L, "egress-unavailable", 1L),
                counts(consumerStatus().path("blocked")));
        assertEquals(3, written.size(), "each blocked SYN is answered");
        assertEquals(1, sentTo.stream().filter(target -> target[0] == 44L).count(), "the offered egress was not sent to");

        // And the person reading it is shown the lines for the two the catalogue refuses.
        List<String> lines = EgressView.lines(MAPPER.valueToTree(mesh.status()));
        assertTrue(lines.contains("    egress peer 42: not offered to this device by the server's egress catalog"),
                String.join("\n", lines));
        assertTrue(lines.contains("    egress peer 43: online, but its client does not support peer egress"),
                String.join("\n", lines));
        assertTrue(lines.contains("    egress peer 45: offline, so its rules have nowhere to send"), String.join("\n", lines));
        assertFalse(String.join("\n", lines).contains("egress peer 44"), String.join("\n", lines));
    }

    /**
     * A new control session forgets that a catalogue came: an egress the old one left out is
     * unknown again, and is sent to, until this session's server says otherwise.
     */
    @Test
    void aNewControlSessionForgetsTheCatalogueCame() {
        available.put(2L, true);
        newMesh().applyRules(List.of(rule("203.0.113.0/24", 2L)));
        mesh.newControlSession();
        mesh.applyEgressCatalog(catalogue(4, "{\"clientId\":9,\"egressVersion\":1}"));
        clearSent();
        assertTrue(mesh.handleOutbound(syn("203.0.113.10", 40000)));
        assertEquals(0, sentTo.size(), "a not-offered egress was sent to");

        mesh.newControlSession();
        assertTrue(mesh.handleOutbound(syn("203.0.113.10", 40001)));
        assertEquals(1, sentTo.size(), "an unknown egress was not sent to");
        assertEquals("unknown", peer(consumerStatus(), 2L).path("standing").asText());
    }

    /** The lines the spec pins for these problems, read from the spec itself, with the id put in. */
    private static List<String> pinnedLines() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        Path spec = null;
        for (int depth = 0; depth < 8 && directory != null && spec == null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("spec").resolve("peer-egress.md");
            if (Files.exists(candidate)) {
                spec = candidate;
            }
            directory = directory.getParent();
        }
        assertNotNull(spec, "cannot locate protocol/spec/peer-egress.md");
        List<String> text = Files.readAllLines(spec, StandardCharsets.UTF_8);
        int section = text.indexOf("### 能力不支持");
        assertTrue(section >= 0, "the spec has no 能力不支持 section");
        int open = text.subList(section, text.size()).indexOf("```text") + section;
        int close = text.subList(open + 1, text.size()).indexOf("```") + open + 1;
        List<String> block = text.subList(open + 1, close);
        assertEquals(6, block.size(), block.toString());
        return block;
    }

    private static String withId(String line, long id) {
        return line.replaceAll("\\bN\\b", Long.toString(id));
    }

    /**
     * Byte for byte the spec's lines, in its order: for each peer the first problem that holds --
     * offline, not offered, unsupported, no path -- and the server line once, after the peers,
     * when the catalogue's state is none.
     */
    @Test
    void theViewPrintsThePinnedLinesInThePinnedOrder() throws Exception {
        List<String> pinned = pinnedLines();
        JsonNode section = MAPPER.readTree("""
                {"consumer": {"active": true, "flows": 0, "catalog": "none",
                  "rules": [],
                  "routes": [],
                  "peers": [{"clientId": 41, "online": false, "standing": "offered", "path": "none", "flows": 0},
                            {"clientId": 42, "online": true, "standing": "not-offered", "path": "none", "flows": 0},
                            {"clientId": 43, "online": true, "standing": "unsupported", "path": "direct", "flows": 0},
                            {"clientId": 44, "online": true, "standing": "offered", "path": "none", "flows": 0},
                            {"clientId": 45, "online": false, "standing": "not-offered", "path": "none", "flows": 0},
                            {"clientId": 46, "online": true, "standing": "unsupported", "path": "none", "flows": 0},
                            {"clientId": 47, "online": true, "standing": "unknown", "path": "direct", "flows": 0}],
                  "blocked": {"egress-not-offered": 2, "egress-unsupported": 1}},
                 "egress": {"active": false}}""");
        List<String> lines = EgressView.lines(section);
        List<String> want = new ArrayList<>(List.of(
                "    egress peer 41: offline, so its rules have nowhere to send",
                "      fix: start egress device 41 or restore its connection; until then its destinations are blocked, not sent locally",
                withId(pinned.get(0), 42), withId(pinned.get(1), 42),
                withId(pinned.get(2), 43), withId(pinned.get(3), 43),
                "    egress peer 44: online but no path to it yet",
                "      fix: wait for a direct or relay path; if it lasts, check that both devices reach the server over UDP",
                "    egress peer 45: offline, so its rules have nowhere to send",
                "      fix: start egress device 45 or restore its connection; until then its destinations are blocked, not sent locally",
                withId(pinned.get(2), 46), withId(pinned.get(3), 46),
                pinned.get(4), pinned.get(5),
                "    blocked: egress-not-offered=2, egress-unsupported=1"));
        assertEquals(want, lines.subList(1, lines.size() - 1), String.join("\n", lines));
        // The id lands where the spec's N is, and nowhere else.
        assertEquals("    egress peer 42: not offered to this device by the server's egress catalog", lines.get(3));
        assertEquals("      fix: upgrade the client on egress device 43; until then its destinations are blocked,"
                + " not sent locally", lines.get(6));

        // The server line only when the state is none: not while waiting, not once received, and
        // not from a state file written before the field existed.
        for (String catalog : List.of("\"waiting\"", "\"received\"", "null")) {
            JsonNode other = MAPPER.readTree(section.toString().replace("\"catalog\":\"none\"", "\"catalog\":" + catalog));
            assertFalse(String.join("\n", EgressView.lines(other)).contains("server: sent no egress catalog"), catalog);
        }
        JsonNode older = MAPPER.readTree(section.toString().replace("\"catalog\":\"none\",", ""));
        assertFalse(String.join("\n", EgressView.lines(older)).contains("server:"), "a state file without catalog");
    }
}
