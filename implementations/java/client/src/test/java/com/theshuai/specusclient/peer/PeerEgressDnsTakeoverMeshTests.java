package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressRule;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The system DNS takeover inside the mesh: taken over once the pool's route is in, refused while it
 * is not, given back when the routes go or the client stops, and taken again -- or phase two
 * stopped -- when the network changes. The machine is a fake; nothing touches this machine's DNS.
 */
class PeerEgressDnsTakeoverMeshTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String POOL = "198.18.0.0/15";
    private static final long EPOCH = 1_800_000_000_000L;

    @TempDir
    Path directory;

    private PeerEgressMesh mesh;
    private List<String> interfaces = List.of("192.168.1.0/24");
    private String poolOwner;
    private final List<String> installed = new ArrayList<>();

    @AfterEach
    void stop() {
        if (mesh != null) {
            mesh.close();
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
        public boolean dnsTakeover() {
            return true;
        }

        @Override
        public List<String> localInterfaceCidrs() {
            return interfaces;
        }

        @Override
        public List<String> localInterfaceAddresses() {
            return List.of("192.168.1.20");
        }

        @Override
        public Map<Long, Boolean> egressAvailability() {
            return Map.of(2L, true);
        }
    }

    private final class Commander implements PeerEgressRouteInstaller.Commander {
        @Override
        public PeerEgressRouteInstaller.Conflict conflict(PeerEgressRoutePlanner.Route route) {
            return route.cidr().equals(poolOwner) ? new PeerEgressRouteInstaller.Conflict(true, poolOwner + " dev wg0")
                    : PeerEgressRouteInstaller.Conflict.none();
        }

        @Override
        public void install(PeerEgressRoutePlanner.Route route) {
            installed.add(route.cidr());
        }

        @Override
        public void remove(PeerEgressRoutePlanner.Route route) {
            installed.remove(route.cidr());
        }
    }

    private PeerEgressDnsTakeoverTests.FakeMachine newMesh() {
        mesh = new PeerEgressMesh(new Host(), (protocol, host, port, timeoutMs) -> {
            throw new IOException("nothing is dialled here");
        }, new Commander());
        PeerEgressDnsTakeoverTests.FakeMachine machine = PeerEgressDnsTakeoverTests.resolved();
        mesh.dnsMachine = machine;
        mesh.dnsForwarder = (query, tcp, upstreams) -> null;
        return machine;
    }

    private static List<PeerEgressRule> rules() {
        PeerEgressRule rule = new PeerEgressRule();
        rule.setMatch("example.com");
        rule.setAction(PeerEgressRule.ACTION_EGRESS);
        rule.setEgressClientId(2L);
        return List.of(rule);
    }

    private JsonNode dns() {
        return MAPPER.valueToTree(mesh.status()).path("consumer").path("dns");
    }

    private Path journal() {
        return directory.resolve(PeerEgressDnsTakeover.JOURNAL_FILE);
    }

    /**
     * With the pool's route in, the system's DNS is taken over, the journal sits beside the route
     * record, the status says so, and the responder forwards to the upstreams read from the system.
     * Withdrawing the routes gives the system's DNS back first.
     */
    @Test
    void takesOverOnceThePoolRouteIsIn() {
        PeerEgressDnsTakeoverTests.FakeMachine machine = newMesh();
        mesh.reconcile(rules(), EPOCH);

        JsonNode dns = dns();
        assertTrue(dns.path("active").asBoolean());
        assertTrue(dns.path("takeover").asBoolean(), dns.toString());
        assertEquals("committed", dns.path("journal").asText());
        assertEquals("[\"192.168.1.1\"]", dns.path("upstreams").toString());
        assertTrue(dns.path("code").isMissingNode(), dns.toString());
        assertEquals(List.of("192.168.1.1"), mesh.dnsResponder().stats().upstreams(),
                "the responder does not forward to the upstreams the takeover recorded");
        assertTrue(Files.exists(journal()), "the journal is not beside the route install record");
        assertTrue(machine.changes().contains("resolvectl dns specus0 198.18.0.1"));

        machine.ran.clear();
        mesh.withdrawRoutes();
        assertEquals(List.of("resolvectl revert specus0", "resolvectl flush-caches"), machine.changes());
        assertFalse(Files.exists(journal()));
        assertFalse(dns().path("takeover").asBoolean());
    }

    /** A pool route somebody else holds refuses the takeover; phase two runs regardless. */
    @Test
    void refusesWhileThePoolRouteIsNotInstalled() {
        poolOwner = POOL;
        PeerEgressDnsTakeoverTests.FakeMachine machine = newMesh();
        mesh.reconcile(rules(), EPOCH);

        JsonNode dns = dns();
        assertTrue(dns.path("active").asBoolean(), "phase two stopped with the takeover");
        assertFalse(dns.path("takeover").asBoolean());
        assertEquals(PeerEgressCodes.DNS_TAKEOVER_REFUSED, dns.path("code").asText());
        assertEquals("pool-route-not-installed", dns.path("reason").asText());
        assertEquals("none", dns.path("journal").asText());
        assertTrue(machine.ran.isEmpty(), "the system was read or changed with no route to the responder");
    }

    /**
     * A new network is given back and taken again, so its own DNS becomes the upstreams; a network
     * whose addresses fall in the pool stops phase two and gives back.
     */
    @Test
    void followsTheNetwork() {
        AtomicReference<String> network = new AtomicReference<>("eth0|192.168.1.20");
        PeerEgressDnsTakeoverTests.FakeMachine machine = newMesh();
        mesh.networkFingerprint = network::get;
        mesh.reconcile(rules(), EPOCH);
        assertTrue(dns().path("takeover").asBoolean());

        machine.ran.clear();
        network.set("wlan0|10.1.2.3");
        machine.answer(PeerEgressDnsTakeoverTests.RESOLVECTL_DNS, "Global:\nLink 3 (wlan0): 10.1.2.1\n");
        mesh.reconcile(rules(), EPOCH + PeerEgressDnsTakeover.NETWORK_CHECK_MS);
        assertEquals(List.of("resolvectl revert specus0", "resolvectl flush-caches", "resolvectl dns specus0 198.18.0.1",
                "resolvectl domain specus0 ~.", "resolvectl flush-caches"), machine.changes());
        assertEquals("[\"10.1.2.1\"]", dns().path("upstreams").toString(), "the old network's DNS is still forwarded to");

        machine.ran.clear();
        network.set("wlan1|198.18.5.20");
        interfaces = List.of("198.18.5.0/24");
        mesh.reconcile(rules(), EPOCH + 2 * PeerEgressDnsTakeover.NETWORK_CHECK_MS);
        JsonNode dns = dns();
        assertFalse(dns.path("active").asBoolean(), "phase two ran on a network inside the pool");
        assertEquals(PeerEgressCodes.FAKE_IP_POOL_INVALID, dns.path("code").asText());
        assertFalse(dns.path("takeover").asBoolean());
        assertEquals(List.of("resolvectl revert specus0", "resolvectl flush-caches"), machine.changes());
        assertFalse(installed.contains(POOL), "the pool route outlived phase two");
        assertNull(mesh.dnsResponder());
    }

    /** Stopping the client gives the system's DNS back. */
    @Test
    void givesBackWhenTheClientStops() {
        PeerEgressDnsTakeoverTests.FakeMachine machine = newMesh();
        mesh.reconcile(rules(), EPOCH);
        machine.ran.clear();

        mesh.close();
        assertEquals(List.of("resolvectl revert specus0", "resolvectl flush-caches"), machine.changes());
        assertFalse(Files.exists(journal()));
        mesh = null;
    }

    /** A journal another running client owns is left alone, and the status says why this one does not take over. */
    @Test
    void leavesARunningClientsJournalAlone() throws IOException {
        PeerEgressDnsTakeover.writeJournal(journal(), new PeerEgressDnsTakeover.Journal("committed", "linux-resolved", 777,
                "198.18.0.1", "specus0", List.of("192.168.1.1"), EPOCH, null, List.of()));
        PeerEgressDnsTakeoverTests.FakeMachine machine = newMesh();
        machine.running = pid -> pid == 777;
        mesh.reconcile(rules(), EPOCH);
        assertTrue(machine.changes().isEmpty(), "a running client's takeover was touched: " + machine.changes());
        assertEquals(777, PeerEgressDnsTakeover.readJournal(journal()).pid());
        JsonNode dns = dns();
        assertTrue(dns.path("active").asBoolean(), dns.toString());
        assertFalse(dns.path("takeover").asBoolean(), dns.toString());
        assertEquals("EGRESS_DNS_TAKEOVER_FAILED", dns.path("code").asText(), dns.toString());
        assertEquals("the system DNS is taken over by another running client (PID 777)", dns.path("error").asText());
        assertEquals("none", dns.path("journal").asText());
    }

    /** A journal a killed client left is given back before this client takes over. */
    @Test
    void givesBackALeftoverJournalFirst() throws IOException {
        PeerEgressDnsTakeover.writeJournal(journal(), new PeerEgressDnsTakeover.Journal("committed", "linux-resolved", 1,
                "198.18.0.1", "specus0", List.of("192.168.1.1"), EPOCH, null, List.of()));
        PeerEgressDnsTakeoverTests.FakeMachine machine = newMesh();
        mesh.reconcile(rules(), EPOCH);
        List<String> changes = machine.changes();
        assertEquals(List.of("resolvectl revert specus0", "resolvectl flush-caches"), changes.subList(0, 2),
                "the leftover was not given back first: " + changes);
        assertTrue(dns().path("takeover").asBoolean());
    }
}
