package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Kind;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Route;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Putting back what the routing table lost.
 *
 * <p>The comparison is pinned by the shared vector; what is argued here is what the installer does
 * with it -- which routes are taken out and put back, which are given up as somebody else's, and
 * what happens to the journal in each case -- and that the mesh's tick runs it and backs off.
 */
class PeerEgressDriftTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long START = 1_758_196_800_000L;

    @TempDir
    Path directory;

    /**
     * A routing table that can be read back. The physical routes are what a test changes to move
     * the machine to another network; where each bypass was pointed when it was installed stays
     * put, the way a real row does.
     */
    static final class TableCommander implements PeerEgressRouteInstaller.Commander {
        final Map<String, Route> table = new TreeMap<>();
        final Map<String, String> foreign = new HashMap<>();
        final Map<String, IOException> installErr = new HashMap<>();
        final List<String> installLog = new ArrayList<>();
        final List<String> removeLog = new ArrayList<>();
        final List<String> conflictLog = new ArrayList<>();
        String tunnel = "specus0";
        List<PeerEgressSocketBinding.Route> physical = new ArrayList<>(List.of(
                new PeerEgressSocketBinding.Route("0.0.0.0/0", "eth0", "192.0.2.1", 100, true)));
        final Map<String, PeerEgressSocketBinding.Route> hops = new HashMap<>();
        IOException tableError;

        @Override
        public PeerEgressRouteInstaller.Conflict conflict(Route route) {
            conflictLog.add(route.cidr());
            String existing = foreign.get(route.cidr());
            return existing == null
                    ? PeerEgressRouteInstaller.Conflict.none()
                    : new PeerEgressRouteInstaller.Conflict(true, existing);
        }

        @Override
        public void install(Route route) throws IOException {
            IOException failure = installErr.get(route.cidr());
            if (failure != null) {
                throw failure;
            }
            if (route.kind() == Kind.BYPASS) {
                // Resolved the way the real commanders resolve it: from the physical routes, now.
                PeerEgressSocketBinding.Route hop = PeerEgressSocketBinding.selectBypassHop(physical, tunnel,
                        List.of(), route.cidr().substring(0, route.cidr().length() - 3));
                if (hop == null) {
                    throw new PeerEgressSocketBinder.NoPhysicalRouteException(route.cidr());
                }
                hops.put(route.cidr(), hop);
            }
            table.put(route.cidr(), route);
            installLog.add(route.cidr());
        }

        @Override
        public void remove(Route route) {
            table.remove(route.cidr());
            hops.remove(route.cidr());
            removeLog.add(route.cidr());
        }

        @Override
        public PeerEgressRouteInstaller.Table table() throws IOException {
            if (tableError != null) {
                throw tableError;
            }
            List<PeerEgressSocketBinding.Route> rows = new ArrayList<>(physical);
            for (Map.Entry<String, Route> entry : table.entrySet()) {
                if (entry.getValue().kind() == Kind.BYPASS) {
                    PeerEgressSocketBinding.Route hop = hops.get(entry.getKey());
                    rows.add(new PeerEgressSocketBinding.Route(entry.getKey(), hop.iface(), hop.gateway(), 0, true));
                } else {
                    rows.add(new PeerEgressSocketBinding.Route(entry.getKey(), tunnel, "", 0, true));
                }
            }
            return new PeerEgressRouteInstaller.Table(rows, tunnel);
        }

        /** Drops a route from the table behind the journal's back, the way an interface going down does. */
        void lose(String cidr) {
            table.remove(cidr);
            hops.remove(cidr);
        }
    }

    private TableCommander commander;
    private PeerEgressRouteInstaller installer;
    private PeerEgressMesh mesh;

    @AfterEach
    void stop() {
        if (mesh != null) {
            mesh.close();
        }
    }

    private static Route tun(String cidr) {
        return new Route(cidr, Kind.TUN, "rule:" + cidr);
    }

    private static Route bypass(String cidr) {
        return new Route(cidr, Kind.BYPASS, "bypass");
    }

    private void fixture() {
        commander = new TableCommander();
        installer = new PeerEgressRouteInstaller(commander, directory.resolve("egress-routes.json"));
        PeerEgressRouteInstaller.ApplyResult result =
                installer.apply(List.of(bypass("203.0.113.7/32"), tun("203.0.113.0/24")));
        assertNull(result.error());
        assertEquals(2, result.added().size());
    }

    /** A bypass being put back has its stale row still in the table; it must not choose itself. */
    @Test
    void theHopFromTheTableLeavesItsOwnRouteOut() throws IOException {
        PeerEgressSocketBinding.Route hop = PeerEgressSocketBinding.bypassHopFromTable("198.51.100.7", "specus0",
                () -> List.of(
                        new PeerEgressSocketBinding.Route("0.0.0.0/0", "wlan0", "10.0.0.1", 600, true),
                        new PeerEgressSocketBinding.Route("198.51.100.7/32", "eth0", "192.168.64.1", 0, true)));
        assertEquals("wlan0", hop.iface());
        assertEquals("10.0.0.1", hop.gateway());
    }

    /** A healthy table costs nothing: no removals, no installs, no conflict queries. */
    @Test
    void repairLeavesAHealthyTableAlone() {
        fixture();
        int installs = commander.installLog.size();
        int queries = commander.conflictLog.size();

        PeerEgressRouteInstaller.RepairResult result = installer.repair();
        assertNull(result.tableError());
        assertNull(result.error());
        assertTrue(result.repaired().isEmpty() && result.lost().isEmpty(), "repair: " + result);
        assertEquals(installs, commander.installLog.size());
        assertEquals(queries, commander.conflictLog.size());
        assertTrue(commander.removeLog.isEmpty(), "a healthy table was touched: " + commander.removeLog);
    }

    /** A route the kernel dropped is put back, and stays in the journal throughout. */
    @Test
    void repairPutsBackARouteTheTableLost() {
        fixture();
        commander.lose("203.0.113.0/24");

        PeerEgressRouteInstaller.RepairResult result = installer.repair();
        assertNull(result.error());
        assertEquals(1, result.repaired().size(), "repair: " + result);
        assertEquals(PeerEgressSocketBinding.DRIFT_MISSING, result.repaired().get(0).reason());
        assertEquals(2, Collections.frequency(commander.installLog, "203.0.113.0/24"));
        assertTrue(installer.owns("203.0.113.0/24"), "the route left the journal while it was being put back");
        assertTrue(installer.repair().repaired().isEmpty(), "a second repair found more to do");
    }

    /**
     * Back from sleep on another network: the bypass still names the old gateway, so it is moved to
     * the new one. The tunnel route, which did not move, is not touched.
     */
    @Test
    void repairMovesABypassToTheNewGateway() {
        fixture();
        commander.physical = new ArrayList<>(List.of(
                new PeerEgressSocketBinding.Route("0.0.0.0/0", "wlan0", "10.0.0.1", 600, true)));

        PeerEgressRouteInstaller.RepairResult result = installer.repair();
        assertNull(result.error());
        assertEquals(1, result.repaired().size(), "repair: " + result);
        assertEquals(PeerEgressSocketBinding.DRIFT_MOVED, result.repaired().get(0).reason());
        assertEquals("203.0.113.7/32", result.repaired().get(0).route().cidr());
        assertEquals(List.of("203.0.113.7/32"), commander.removeLog, "want only the bypass taken out");
        PeerEgressSocketBinding.Route hop = commander.hops.get("203.0.113.7/32");
        assertEquals("wlan0", hop.iface());
        assertEquals("10.0.0.1", hop.gateway());
        assertTrue(installer.repair().repaired().isEmpty(), "a second repair found more to do");
    }

    /**
     * A prefix somebody else took while ours was gone is theirs: reported, dropped from the
     * journal, and not installed over.
     */
    @Test
    void repairGivesUpAPrefixSomebodyElseTook() throws IOException {
        fixture();
        String existing = "203.0.113.0/24 via 192.0.2.1 dev eth0";
        commander.lose("203.0.113.0/24");
        commander.physical.add(new PeerEgressSocketBinding.Route("203.0.113.0/24", "eth0", "192.0.2.1", 0, true));
        commander.foreign.put("203.0.113.0/24", existing);
        int installs = commander.installLog.size();

        PeerEgressRouteInstaller.RepairResult result = installer.repair();
        assertNull(result.error());
        assertTrue(result.repaired().isEmpty());
        assertEquals(1, result.lost().size(), "repair: " + result);
        assertEquals("203.0.113.0/24", result.lost().get(0).route().cidr());
        assertEquals(existing, result.lost().get(0).existing());
        assertEquals(installs, commander.installLog.size(), "the other route was installed over");
        assertFalse(commander.removeLog.contains("203.0.113.0/24"), "the other route was taken out");
        assertFalse(installer.owns("203.0.113.0/24"), "a prefix somebody else holds is still in the journal");
        assertFalse(Files.readString(directory.resolve("egress-routes.json")).contains("203.0.113.0/24"),
                "the journal on disk still lists the prefix");
    }

    /** A reinstall that fails keeps the route owned, so the next repair tries again. */
    @Test
    void repairKeepsARouteItCouldNotPutBack() {
        fixture();
        commander.lose("203.0.113.0/24");
        commander.installErr.put("203.0.113.0/24", new IOException("permission denied"));

        PeerEgressRouteInstaller.RepairResult result = installer.repair();
        assertNotNull(result.error());
        assertTrue(result.repaired().isEmpty());
        assertTrue(installer.owns("203.0.113.0/24"), "a route that could not be put back was dropped");

        commander.installErr.clear();
        PeerEgressRouteInstaller.RepairResult again = installer.repair();
        assertNull(again.error());
        assertEquals(1, again.repaired().size());
    }

    @Test
    void repairReportsAnUnreadableTable() {
        fixture();
        commander.tableError = new IOException("ip: not found");

        PeerEgressRouteInstaller.RepairResult result = installer.repair();
        assertNotNull(result.tableError());
        assertTrue(result.repaired().isEmpty() && result.lost().isEmpty());
    }

    // ---- the tick --------------------------------------------------------------------------------

    private final class Host implements PeerEgressMesh.Host {
        List<PeerEgressRule> rules = List.of();

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
            return "100.96.0.1";
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
        public List<PeerEgressRule> consumerRules() {
            return rules;
        }
    }

    private Host meshWithRule() {
        Host host = new Host();
        PeerEgressRule rule = new PeerEgressRule();
        rule.setMatch("203.0.113.0/24");
        rule.setAction(PeerEgressRule.ACTION_EGRESS);
        rule.setEgressClientId(2L);
        host.rules = List.of(rule);
        commander = new TableCommander();
        mesh = new PeerEgressMesh(host, (protocol, target, port, timeoutMs) -> {
            throw new IOException("nothing is dialled in this test");
        }, commander);
        return host;
    }

    private JsonNode consumer() {
        return MAPPER.valueToTree(mesh.status()).path("consumer");
    }

    /** The tick puts routes back, and backs off when it cannot. */
    @Test
    void theTickPutsBackRoutesTheTableLost() {
        Host host = meshWithRule();
        long now = START;
        mesh.reconcile(host.rules, now);
        long applied = consumer().path("appliedAtUnixMs").asLong();

        commander.lose("203.0.113.0/24");
        now += 5_000;
        mesh.reconcile(host.rules, now);
        assertEquals(2, Collections.frequency(commander.installLog, "203.0.113.0/24"),
                "want the route put back on the tick: " + commander.installLog);
        assertEquals(applied, consumer().path("appliedAtUnixMs").asLong(),
                "putting a route back counted as applying the plan");

        commander.lose("203.0.113.0/24");
        commander.installErr.put("203.0.113.0/24", new IOException("permission denied"));
        now += 5_000;
        mesh.reconcile(host.rules, now);
        int attempts = commander.installLog.size();
        now += 5_000;
        mesh.reconcile(host.rules, now);
        assertEquals(attempts, commander.installLog.size(),
                "a failed reinstall was retried on the next tick rather than after the interval");
        commander.installErr.clear();
        now += PeerEgressRoutePlanner.RETRY_AFTER_MILLIS;
        mesh.reconcile(host.rules, now);
        assertTrue(commander.table.containsKey("203.0.113.0/24"),
                "the route was not put back once the interval had passed");
    }

    /**
     * A prefix another route took shows in the status as not installed, and the plan asks for it
     * again after the interval.
     */
    @Test
    void aPrefixLostToAnotherRouteIsReported() {
        Host host = meshWithRule();
        long now = START;
        mesh.reconcile(host.rules, now);

        String existing = "203.0.113.0/24 via 192.0.2.1 dev eth0";
        commander.lose("203.0.113.0/24");
        commander.physical.add(new PeerEgressSocketBinding.Route("203.0.113.0/24", "eth0", "192.0.2.1", 0, true));
        commander.foreign.put("203.0.113.0/24", existing);
        now += 5_000;
        mesh.reconcile(host.rules, now);

        JsonNode reported = null;
        for (JsonNode route : consumer().path("routes")) {
            if (route.path("cidr").asText().equals("203.0.113.0/24")) {
                reported = route;
            }
        }
        assertNotNull(reported, "the lost prefix is missing from the status");
        assertFalse(reported.path("installed").asBoolean());
        assertEquals(existing, reported.path("conflict").asText());

        // The other route goes away; the plan, marked troubled, asks again after the interval.
        commander.physical.remove(1);
        commander.foreign.clear();
        now += 5_000;
        mesh.reconcile(host.rules, now);
        assertFalse(commander.table.containsKey("203.0.113.0/24"), "the prefix was reinstalled before the interval");
        now += PeerEgressRoutePlanner.RETRY_AFTER_MILLIS;
        mesh.reconcile(host.rules, now);
        assertTrue(commander.table.containsKey("203.0.113.0/24"), "the prefix was not asked for again");
    }
}
