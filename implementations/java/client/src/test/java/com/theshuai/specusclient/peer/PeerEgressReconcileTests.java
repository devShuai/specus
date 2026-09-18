package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressRule;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Keeping the consumer's routes true while the process runs.
 *
 * <p>The plan is recomputed on the mesh's tick and applied only when it changed or when a retry is
 * due. What these cases pin is the wiring around that: what the plan is fed, when the installer is
 * asked to act, and what happens to the routes when the device is not there.
 */
class PeerEgressReconcileTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long START = 1_758_196_800_000L;

    @TempDir
    Path directory;

    private final MutableHost host = new MutableHost();
    private final LoggingCommander commander = new LoggingCommander();
    private final Map<String, InetAddress[]> lookups = new HashMap<>();
    private PeerEgressMesh mesh;
    private long now = START;

    /** A host whose answers the test changes between ticks. */
    private final class MutableHost implements PeerEgressMesh.Host {
        List<PeerEgressRule> rules = List.of();
        boolean deviceUp = true;
        List<String> bypass = List.of();
        List<String> peers = List.of();

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
            return peers;
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

        @Override
        public boolean deviceReady() {
            return deviceUp;
        }

        @Override
        public List<String> bypassHosts() {
            return bypass;
        }
    }

    /** A routing table that records what it was asked, and whose conflicts the test chooses. */
    private static final class LoggingCommander implements PeerEgressRouteInstaller.Commander {
        final Map<String, String> foreign = new HashMap<>();
        final List<String> conflictLog = new ArrayList<>();
        final List<String> installLog = new ArrayList<>();
        final List<String> removeLog = new ArrayList<>();

        @Override
        public PeerEgressRouteInstaller.Conflict conflict(PeerEgressRoutePlanner.Route route) {
            conflictLog.add(route.cidr());
            String existing = foreign.get(route.cidr());
            return existing == null
                    ? PeerEgressRouteInstaller.Conflict.none()
                    : new PeerEgressRouteInstaller.Conflict(true, existing);
        }

        @Override
        public void install(PeerEgressRoutePlanner.Route route) {
            installLog.add(route.cidr());
        }

        @Override
        public void remove(PeerEgressRoutePlanner.Route route) {
            removeLog.add(route.cidr());
        }
    }

    @AfterEach
    void stop() {
        if (mesh != null) {
            mesh.close();
        }
    }

    private PeerEgressMesh newMesh(PeerEgressRule... rules) {
        host.rules = List.of(rules);
        mesh = new PeerEgressMesh(host, (protocol, target, port, timeoutMs) -> {
            throw new IOException("nothing is dialled in this test");
        }, commander, name -> {
            InetAddress[] answer = lookups.get(name);
            if (answer == null) {
                throw new UnknownHostException(name);
            }
            return answer;
        });
        return mesh;
    }

    private static PeerEgressRule egressTo(String match, long target) {
        PeerEgressRule rule = new PeerEgressRule();
        rule.setMatch(match);
        rule.setAction(PeerEgressRule.ACTION_EGRESS);
        rule.setEgressClientId(target);
        return rule;
    }

    private JsonNode consumerSection() {
        return MAPPER.valueToTree(mesh.status()).path("consumer");
    }

    /**
     * With no rules there is nothing for a consumer to do, so none is built and the status says
     * so. The journal is still read, which the next case proves.
     */
    @Test
    void buildsNoConsumerWithoutRules() {
        newMesh();
        mesh.reconcile(List.of(), now);

        assertFalse(consumerSection().path("active").asBoolean(),
                "the status reports a consumer with no rules as active");
    }

    /**
     * A journal from a process that was killed describes routes whose interface is gone. They are
     * taken back on the first reconcile -- with no rules at all, which is the case that used to
     * leave them.
     */
    @Test
    void takesBackRoutesLeftByAPreviousRun() throws IOException {
        Files.writeString(directory.resolve("egress-routes.json"), """
                {"version":1,"routes":[
                  {"cidr":"198.51.100.7/32","kind":"bypass","origin":"bypass"},
                  {"cidr":"203.0.113.0/24","kind":"tun","origin":"rule:203.0.113.0/24"}]}
                """);
        newMesh();

        mesh.reconcile(List.of(), now);

        assertTrue(commander.removeLog.contains("203.0.113.0/24"), "removed " + commander.removeLog);
        assertTrue(commander.removeLog.contains("198.51.100.7/32"), "removed " + commander.removeLog);
        assertFalse(Files.exists(directory.resolve("egress-routes.json")),
                "the journal still exists after its routes were taken back");
    }

    /**
     * An unchanged plan is not reapplied, and the table is not asked about it again. When a peer's
     * endpoint falls under a rule, its bypass goes in on the next tick; when the peer goes, so
     * does the bypass.
     */
    @Test
    void appliesOnlyWhenThePlanChanges() {
        newMesh(egressTo("203.0.113.0/24", 2L));

        mesh.reconcile(host.rules, now);
        assertTrue(commander.installLog.contains("203.0.113.0/24"), "installed " + commander.installLog);
        long first = consumerSection().path("appliedAtUnixMs").asLong();
        int queries = commander.conflictLog.size();

        now += 5_000;
        mesh.reconcile(host.rules, now);
        assertEquals(first, consumerSection().path("appliedAtUnixMs").asLong(),
                "an unchanged plan was applied again");
        assertEquals(queries, commander.conflictLog.size(), "an unchanged plan queried the table again");

        host.peers = List.of("203.0.113.7");
        now += 5_000;
        mesh.reconcile(host.rules, now);
        assertTrue(commander.installLog.contains("203.0.113.7/32"),
                "the peer's endpoint under the rule got no bypass: " + commander.installLog);
        assertEquals(now, consumerSection().path("appliedAtUnixMs").asLong(),
                "a changed plan was not applied on the tick it changed");

        host.peers = List.of();
        now += 5_000;
        mesh.reconcile(host.rules, now);
        assertTrue(commander.removeLog.contains("203.0.113.7/32"),
                "the departed peer's bypass was left in place: " + commander.removeLog);
        assertFalse(commander.removeLog.contains("203.0.113.0/24"),
                "the rule's own route was lost while the bypass came and went");
    }

    /**
     * A prefix somebody else owns is asked about again after the interval, not on every tick, and
     * is installed once the other route is gone.
     */
    @Test
    void retriesAConflictAfterTheInterval() {
        newMesh(egressTo("203.0.113.0/24", 2L));
        commander.foreign.put("203.0.113.0/24", "203.0.113.0/24 via 192.0.2.1 dev eth0");

        mesh.reconcile(host.rules, now);
        assertEquals(1, commander.conflictLog.size());
        assertTrue(commander.installLog.isEmpty(), "a contested prefix was installed");

        now += 5_000;
        mesh.reconcile(host.rules, now);
        assertEquals(1, commander.conflictLog.size(), "the conflict was retried inside the interval");

        now += PeerEgressRoutePlanner.RETRY_AFTER_MILLIS - 5_000;
        mesh.reconcile(host.rules, now);
        assertEquals(2, commander.conflictLog.size(), "the conflict was not retried after the interval");

        commander.foreign.clear();
        now += PeerEgressRoutePlanner.RETRY_AFTER_MILLIS;
        mesh.reconcile(host.rules, now);
        assertTrue(commander.installLog.contains("203.0.113.0/24"),
                "the route was not installed once the prefix was free: " + commander.installLog);
        for (JsonNode route : consumerSection().path("routes")) {
            assertFalse(route.has("conflict"), "the status still reports the conflict: " + route);
        }
    }

    /** Routes point into the device, so there are none until it is up, and none once it is gone. */
    @Test
    void followsTheDevice() {
        newMesh(egressTo("203.0.113.0/24", 2L));
        host.deviceUp = false;

        mesh.reconcile(host.rules, now);
        assertTrue(commander.installLog.isEmpty(),
                "routes were installed into a device that is not there: " + commander.installLog);
        assertTrue(consumerSection().path("active").asBoolean(),
                "the consumer was not built while the device was down; the rules should still be reported");

        host.deviceUp = true;
        now += 5_000;
        mesh.reconcile(host.rules, now);
        assertTrue(commander.installLog.contains("203.0.113.0/24"),
                "routes were not installed once the device came up: " + commander.installLog);

        host.deviceUp = false;
        now += 5_000;
        mesh.reconcile(host.rules, now);
        assertTrue(commander.removeLog.contains("203.0.113.0/24"),
                "routes were left pointing at a device that went away: " + commander.removeLog);
    }

    /**
     * Everything the tunnel's transport talks to is pinned when a rule covers it, whether it
     * arrived as a URL, a name with a port, or a literal; and an IPv6 answer is not a route.
     */
    @Test
    void pinsTheTransportEndpoints() throws UnknownHostException {
        newMesh(egressTo("203.0.113.0/24", 2L));
        lookups.put("api.example.test", new InetAddress[] {InetAddress.getByName("203.0.113.61")});
        lookups.put("stun.example.test", new InetAddress[] {
            InetAddress.getByName("2001:db8::1"), InetAddress.getByName("203.0.113.60")});
        host.bypass = List.of("https://api.example.test:8443/", "stun.example.test:3478",
                "203.0.113.50", "gone.example.test", "198.51.100.9");

        mesh.reconcile(host.rules, now);

        for (String want : List.of("203.0.113.61/32", "203.0.113.60/32", "203.0.113.50/32")) {
            assertTrue(commander.installLog.contains(want), want + " was not pinned: " + commander.installLog);
        }
        assertFalse(commander.installLog.contains("198.51.100.9/32"),
                "an address no rule covers got a route of its own");
        assertEquals(4, commander.installLog.size(), "installed " + commander.installLog);
    }

    /** The reconcile entry point the mesh calls reads the rules from the host. */
    @Test
    void theTickReadsTheRulesFromTheHost() {
        newMesh(egressTo("203.0.113.0/24", 2L));
        mesh.reconcileRoutes();
        assertTrue(commander.installLog.contains("203.0.113.0/24"), "installed " + commander.installLog);
    }

    /**
     * The resolver reads a URL, a host with a port, and a bare host or literal, and answers from
     * its cache for the TTL -- for a failure as well as for a success.
     */
    @Test
    void theResolverReadsEveryFormAndCaches() throws UnknownHostException {
        Map<String, Integer> calls = new HashMap<>();
        InetAddress api = InetAddress.getByName("203.0.113.61");
        InetAddress stunV6 = InetAddress.getByName("2001:db8::1");
        InetAddress stun = InetAddress.getByName("203.0.113.60");
        PeerEgressBypassResolver resolver = new PeerEgressBypassResolver(name -> {
            calls.merge(name, 1, Integer::sum);
            return switch (name) {
                case "api.example.test" -> new InetAddress[] {api};
                case "stun.example.test" -> new InetAddress[] {stunV6, stun};
                default -> throw new UnknownHostException(name);
            };
        });
        List<String> entries = List.of(
                "https://api.example.test:8443/login", "stun.example.test:3478", "203.0.113.9:443",
                "198.51.100.1", "", "[2001:db8::2]:3478", "gone.example.test", "stun.example.test");

        PeerEgressBypassResolver.Resolution first = resolver.resolve(entries, START);
        assertEquals(List.of("203.0.113.61", "203.0.113.60", "203.0.113.9", "198.51.100.1"), first.addresses());
        assertEquals(List.of("gone.example.test"), first.failed());

        // Inside the TTL nothing is asked again, and the failure is still reported from the cache.
        PeerEgressBypassResolver.Resolution again =
                resolver.resolve(entries, START + PeerEgressBypassResolver.RESOLVE_TTL_MILLIS - 1);
        assertEquals(1, calls.get("api.example.test"));
        assertEquals(1, calls.get("stun.example.test"));
        assertEquals(1, calls.get("gone.example.test"));
        assertEquals(List.of("gone.example.test"), again.failed());

        // At the TTL everything is asked again.
        resolver.resolve(entries, START + PeerEgressBypassResolver.RESOLVE_TTL_MILLIS);
        assertEquals(2, calls.get("api.example.test"));
        assertEquals(2, calls.get("gone.example.test"));
    }
}
