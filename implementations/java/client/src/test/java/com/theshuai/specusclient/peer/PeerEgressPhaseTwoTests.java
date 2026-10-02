package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressDns;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Phase two where it meets the rest of the client: the pool as a route, the status an operator
 * reads, and the catalogue arriving on the control connection. The per-packet decisions have their
 * own vector suite ({@link PeerEgressSteeringVectorTests}); these are the joins around it.
 */
class PeerEgressPhaseTwoTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String VIRTUAL_IP = "100.96.0.1";
    private static final String POOL = PeerEgressDns.DEFAULT_FAKE_IP_CIDR;

    @TempDir
    Path directory;

    private final List<long[]> sentTo = new ArrayList<>();
    private final List<byte[]> sentFrames = new ArrayList<>();
    private boolean takeover = true;
    private String fakeIpCidr = POOL;
    private List<String> interfaces = List.of("192.168.1.0/24", "127.0.0.0/8");
    private Map<Long, Boolean> available = Map.of(2L, true);
    private String failInstallOf;
    private final List<String> installedCidrs = new ArrayList<>();
    private PeerEgressMesh mesh;

    private final class Host implements PeerEgressMesh.Host {
        @Override
        public boolean sendToPeer(long peerId, byte[] frame) {
            synchronized (PeerEgressPhaseTwoTests.this) {
                sentTo.add(new long[] {peerId});
                sentFrames.add(frame.clone());
            }
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
            return meshCidr;
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
            return available;
        }

        @Override
        public boolean dnsTakeover() {
            return takeover;
        }

        @Override
        public String fakeIpCidr() {
            return fakeIpCidr;
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
        public List<String> dnsUpstreams() {
            return upstreams;
        }
    }

    private List<String> upstreams = List.of();
    private String meshCidr = "100.96.0.0/11";

    /**
     * Phase two stopping with no rules -- here because the mesh network the server gives moves over
     * the pool -- still reaches the consumer: it lets go of the pool and the responder, the pool
     * route comes out, and the listen address is nobody's any more.
     */
    @Test
    void phaseTwoStoppingWithNoRulesLetsGoOfThePool() {
        newMesh().applyRules(List.of());
        assertTrue(installedCidrs.contains(POOL));
        assertTrue(mesh.handleOutbound(dnsQueryFrom(VIRTUAL_IP, "example.com")), "the responder did not answer");

        meshCidr = "198.18.0.0/16";
        mesh.applyRules(List.of());

        assertFalse(installedCidrs.contains(POOL), "the pool route outlived phase two");
        assertNull(mesh.dnsResponder());
        assertFalse(mesh.handleOutbound(dnsQueryFrom(VIRTUAL_IP, "example.com")),
                "the consumer still steers by a pool phase two let go of");
        JsonNode consumer = consumerStatus();
        assertFalse(consumer.path("dns").path("active").asBoolean());
        assertEquals(PeerEgressCodes.FAKE_IP_POOL_INVALID, consumer.path("dns").path("code").asText());
        assertNull(route(consumer, POOL));
    }

    /** A routing table that records what it was asked to install and can refuse one prefix. */
    private final class Commander implements PeerEgressRouteInstaller.Commander {
        @Override
        public PeerEgressRouteInstaller.Conflict conflict(PeerEgressRoutePlanner.Route route) {
            return PeerEgressRouteInstaller.Conflict.none();
        }

        @Override
        public void install(PeerEgressRoutePlanner.Route route) throws IOException {
            if (route.cidr().equals(failInstallOf)) {
                throw new IOException("RTNETLINK answers: File exists");
            }
            installedCidrs.add(route.cidr());
        }

        @Override
        public void remove(PeerEgressRoutePlanner.Route route) {
            installedCidrs.remove(route.cidr());
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

    private static PeerEgressRule rule(String match, String action, Long target) {
        PeerEgressRule value = new PeerEgressRule();
        value.setMatch(match);
        value.setAction(action);
        value.setEgressClientId(target);
        return value;
    }

    private static List<PeerEgressRule> rules() {
        return List.of(rule("example.com", PeerEgressRule.ACTION_EGRESS, 2L),
                rule("203.0.113.0/24", PeerEgressRule.ACTION_EGRESS, 2L));
    }

    private static String catalogue(long revision, boolean capable) {
        return "{\"type\":\"egress-catalog\",\"revision\":" + revision + ",\"egresses\":[{\"clientId\":2,"
                + "\"online\":true,\"domainTargetCapable\":" + capable + "}]}";
    }

    private JsonNode consumerStatus() {
        return MAPPER.valueToTree(mesh.status()).path("consumer");
    }

    private static JsonNode route(JsonNode consumer, String cidr) {
        for (JsonNode route : consumer.path("routes")) {
            if (route.path("cidr").asText().equals(cidr)) {
                return route;
            }
        }
        return null;
    }

    private synchronized List<byte[]> frames() {
        return List.copyOf(sentFrames);
    }

    private synchronized void clearFrames() {
        sentFrames.clear();
        sentTo.clear();
    }

    private static byte[] synTo(String destination, int sourcePort) {
        return PeerEgressSegment.build(new PeerEgressSegment.Segment(
                Ipv4Cidr.parseAddress(VIRTUAL_IP), Ipv4Cidr.parseAddress(destination), sourcePort, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]));
    }

    private static PeerEgressFrame.Control control(byte[] frame) {
        PeerEgressFrame.Decoded decoded = PeerEgressFrame.parse(frame);
        return decoded.accepted() && decoded.type() == PeerEgressFrame.TYPE_CONTROL
                ? PeerEgressFrame.decodeControl(decoded.body()) : null;
    }

    /**
     * While phase two runs the pool is a TUN route of its own, owned, journalled and reported like
     * a rule's; the domain rule installs nothing itself.
     */
    @Test
    void thePoolIsARouteWhilePhaseTwoRuns() throws IOException {
        newMesh().applyRules(rules());

        JsonNode pool = route(consumerStatus(), POOL);
        assertNotNull(pool, "the pool route is not in the status");
        assertEquals("tun", pool.path("kind").asText());
        assertEquals(PeerEgressRoutePlanner.ORIGIN_FAKE_IP_POOL, pool.path("origin").asText());
        assertTrue(pool.path("installed").asBoolean());
        assertTrue(installedCidrs.contains(POOL));
        assertEquals(2, consumerStatus().path("routes").size(), "only the pool and the address rule are routed");
        assertTrue(Files.readString(directory.resolve("egress-routes.json")).contains("\"fake-ip-pool\""),
                "the pool route is not journalled");

        mesh.withdrawRoutes();
        assertFalse(installedCidrs.contains(POOL), "the pool route outlived the withdrawal");
    }

    /**
     * While phase two runs the pool is routed and the consumer exists with no rules at all, so an
     * address in the pool reaches something that answers it rather than nothing.
     */
    @Test
    void thePoolIsRoutedAndAnsweredWithNoRules() {
        newMesh().applyRules(List.of());

        JsonNode consumer = consumerStatus();
        assertTrue(consumer.path("active").asBoolean(), "no consumer while phase two runs");
        assertTrue(consumer.path("dns").path("active").asBoolean());
        assertNotNull(route(consumer, POOL), "no pool route without rules");
        assertTrue(installedCidrs.contains(POOL));

        assertTrue(mesh.handleOutbound(synTo("198.18.0.9", 40000)), "a packet into the pool was handed back");
        assertEquals(1L, consumerStatus().path("blocked").path("fake-ip-unmapped").asLong());
    }

    /** Off, the same empty rule set takes nothing over, as before phase two existed. */
    @Test
    void noRulesAndNoPhaseTwoBuildsNothing() {
        takeover = false;
        newMesh().applyRules(List.of());

        assertFalse(consumerStatus().path("active").asBoolean());
        assertTrue(installedCidrs.isEmpty());
        assertFalse(mesh.handleOutbound(synTo("198.18.0.9", 40000)));
    }

    /**
     * A name-bind that did not go takes its packet with it: the egress could only open a flow to the
     * fake address itself. Counted as send-failed and not answered, like any failed send; the flow
     * stays, so the retransmitted SYN carries a name-bind again.
     */
    @Test
    void aFailedNameBindDropsThePacketBehindIt() {
        List<byte[]> sent = new ArrayList<>();
        List<byte[]> toTun = new ArrayList<>();
        boolean[] controlFails = {true};
        PeerEgressConsumer consumer = new PeerEgressConsumer((egress, frame) -> {
            PeerEgressFrame.Decoded decoded = PeerEgressFrame.parse(frame);
            if (decoded.type() == PeerEgressFrame.TYPE_CONTROL && controlFails[0]) {
                return false;
            }
            sent.add(frame);
            return true;
        }, toTun::add);
        PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse(POOL), () -> 0L);
        consumer.configure(List.of(rule("example.com", PeerEgressRule.ACTION_EGRESS, 2L)),
                "100.96.0.0/11", VIRTUAL_IP, pool, 0L);
        consumer.setEgressOnline(2L, true, 0L);
        consumer.setDomainCapable(java.util.Set.of(2L), 0L);
        String fake = pool.query("example.com", 0L).addressText();

        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS, consumer.handleOutbound(synTo(fake, 40000), 1L));
        assertTrue(sent.isEmpty(), "the packet went without its name");
        assertTrue(toTun.isEmpty(), "a failed send was answered");
        assertEquals(1L, consumer.blockedCounts().get("send-failed"));

        controlFails[0] = false;
        assertEquals(PeerEgressConsumer.Outcome.FORWARDED, consumer.handleOutbound(synTo(fake, 40000), 2L));
        assertEquals(2, sent.size(), "the retransmitted SYN did not carry a name-bind");
        assertNotNull(control(sent.get(0)));
    }

    /** An egress whose own configuration runs phase two will not dial its own pool. */
    @Test
    void anEgressRunningPhaseTwoRefusesItsOwnPool() throws InterruptedException {
        newMesh().applyEgressConfig("{\"type\":\"egress-config\",\"enabled\":true,\"revision\":1,\"scope\":\"PUBLIC\","
                + "\"allowedConsumerClientIds\":[7],\"destinationRules\":[{\"cidr\":\"198.18.0.0/15\","
                + "\"protocols\":[\"tcp\"],\"portRanges\":[[1,65535]]}]}");
        byte[] syn = PeerEgressSegment.build(new PeerEgressSegment.Segment(
                Ipv4Cidr.parseAddress("100.96.0.7"), Ipv4Cidr.parseAddress("198.18.0.9"), 40000, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]));
        mesh.handleInboundFrame(7, PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false, syn));

        long deadline = System.nanoTime() + 10_000_000_000L;
        PeerEgressFrame.Control reject = null;
        while (reject == null && System.nanoTime() < deadline) {
            reject = frames().stream().map(PeerEgressPhaseTwoTests::control)
                    .filter(message -> message != null && PeerEgressFrame.CONTROL_FLOW_REJECT.equals(message.type()))
                    .findFirst().orElse(null);
            // Refusals leave through the plane's send queue, on its own thread.
            Thread.sleep(1);
        }
        assertNotNull(reject, "the flow into this node's own pool was not refused");
        assertEquals(PeerEgressCodes.FORBIDDEN_DESTINATION, reject.code());
    }

    @Test
    void noPoolRouteWithoutPhaseTwo() {
        takeover = false;
        newMesh().applyRules(rules());

        assertNull(route(consumerStatus(), POOL), "a pool route without phase two");
        JsonNode domain = consumerStatus().path("rules").get(0);
        assertFalse(domain.path("inForce").asBoolean());
        assertEquals(PeerEgressCodes.RULE_DOMAIN_UNSUPPORTED, domain.path("code").asText());
        assertTrue(consumerStatus().path("dns").isMissingNode(), "consumer.dns without peerEgressDnsTakeover");
    }

    /**
     * A pool route that fails to install is rolled back with the rest of that apply: the address
     * rule's route, which sorts ahead of the pool and went in first, comes out again.
     */
    @Test
    void aFailedPoolRouteIsRolledBack() {
        failInstallOf = POOL;
        newMesh().applyRules(List.of(rule("example.com", PeerEgressRule.ACTION_EGRESS, 2L),
                rule("192.0.2.0/24", PeerEgressRule.ACTION_EGRESS, 2L)));

        JsonNode consumer = consumerStatus();
        assertTrue(consumer.path("rolledBack").asBoolean(), "the failed apply was not rolled back");
        assertFalse(consumer.path("routeError").asText().isEmpty());
        assertTrue(installedCidrs.isEmpty(), "routes from the failed apply were left installed: " + installedCidrs);
        assertEquals(0, consumer.path("routes").size(), consumer.path("routes").toString());
    }

    /** A pool route that would cover an address the tunnel's transport uses pins that address outside. */
    @Test
    void thePoolCapturesForTheBypass() {
        PeerEgressRoutePlanner.Plan plan = PeerEgressRoutePlanner.plan(
                List.of(rule("example.com", PeerEgressRule.ACTION_EGRESS, 2L),
                        rule("198.18.0.0/16", PeerEgressRule.ACTION_EGRESS, 2L)),
                List.of("198.18.7.7", "192.0.2.1"), "100.96.0.0/11", POOL);
        assertEquals(List.of(
                new PeerEgressRoutePlanner.Route("198.18.7.7/32", PeerEgressRoutePlanner.Kind.BYPASS, "bypass"),
                new PeerEgressRoutePlanner.Route(POOL, PeerEgressRoutePlanner.Kind.TUN,
                        PeerEgressRoutePlanner.ORIGIN_FAKE_IP_POOL)), plan.routes());
        assertEquals(List.of(new PeerEgressRoutePlanner.Refusal(1, "198.18.0.0/16", PeerEgressCodes.RULE_FAKE_IP_OVERLAP)),
                plan.refused());
    }

    /**
     * {@code consumer.dns} says whether phase two runs and how full the pool is, rules say their
     * kind, and a domain rule is out of force only for an egress that is online and cannot resolve.
     */
    @Test
    void theStatusSaysWhatPhaseTwoIsDoing() {
        newMesh().applyRules(rules());

        JsonNode consumer = consumerStatus();
        JsonNode dns = consumer.path("dns");
        assertTrue(dns.path("active").asBoolean(), dns.toString());
        assertEquals(POOL, dns.path("pool").asText());
        assertEquals(0, dns.path("mappings").asInt());
        assertEquals(0, dns.path("quarantined").asInt());
        assertTrue(dns.path("code").isMissingNode());
        assertEquals("domain", consumer.path("rules").get(0).path("kind").asText());
        assertEquals("cidr", consumer.path("rules").get(1).path("kind").asText());
        // Online, and no catalogue has said it resolves names.
        assertEquals(PeerEgressCodes.RULE_EGRESS_NO_DOMAIN, consumer.path("rules").get(0).path("code").asText());

        mesh.applyEgressCatalog(catalogue(1, true));
        mesh.fakeIpPool().query("example.com");
        consumer = consumerStatus();
        assertTrue(consumer.path("rules").get(0).path("inForce").asBoolean(), consumer.path("rules").toString());
        assertEquals(1, consumer.path("dns").path("mappings").asInt());
        assertEquals(1, consumer.path("peers").size());

        // Offline, the rule is right and waiting, whatever the catalogue says.
        available = Map.of();
        mesh.applyEgressCatalog(catalogue(2, false));
        mesh.syncEgressAvailability(available);
        assertTrue(consumerStatus().path("rules").get(0).path("inForce").asBoolean());
    }

    private static byte[] dnsQueryFrom(String source, String name) {
        return PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(Ipv4Cidr.parseAddress(source),
                Ipv4Cidr.parseAddress("198.18.0.1"), 5353, 53,
                PeerEgressDnsWireVectorTests.query(0x1234, name, PeerEgressDnsMessage.TYPE_A)));
    }

    /**
     * While phase two runs the status says where the responder listens, whom it forwards to and
     * what it answered; a query from this node's mesh address or one of its interfaces is answered,
     * one from anywhere else is dropped and counted in blocked.
     */
    @Test
    void theStatusReportsTheResponder() {
        upstreams = List.of("192.0.2.53", " 127.0.0.1:5353", "resolver.example");
        newMesh();
        mesh.dnsForwarder = (query, tcp, targets) -> null;
        mesh.applyRules(rules());

        JsonNode dns = consumerStatus().path("dns");
        assertEquals("198.18.0.1", dns.path("listen").asText());
        assertEquals("[\"192.0.2.53\",\"127.0.0.1:5353\"]", dns.path("upstreams").toString(),
                "upstreams that are not literal addresses are listed");
        assertEquals("{\"answered\":0,\"forwarded\":0,\"failed\":0}", dns.path("queries").toString());

        assertTrue(mesh.handleOutbound(dnsQueryFrom(VIRTUAL_IP, "example.com")));
        assertTrue(mesh.handleOutbound(dnsQueryFrom("192.168.1.20", "example.com")));
        assertTrue(mesh.handleOutbound(dnsQueryFrom("203.0.113.9", "example.com")), "a query from elsewhere was handed back");
        JsonNode consumer = consumerStatus();
        assertEquals(2, consumer.path("dns").path("queries").path("answered").asLong());
        assertEquals(1, consumer.path("dns").path("mappings").asLong());
        assertEquals(1, consumer.path("blocked").path("dns-not-local").asLong());
    }

    /** Takeover asked for over an unusable pool: no listen address, but upstreams and counts stay. */
    @Test
    void theStatusKeepsUpstreamsAndCountsWhilePhaseTwoIsStopped() {
        fakeIpCidr = "198.18.0.0/25";
        newMesh().applyRules(rules());

        JsonNode dns = consumerStatus().path("dns");
        assertTrue(dns.path("listen").isMissingNode(), "a listen address while phase two is stopped");
        assertEquals("[]", dns.path("upstreams").toString());
        assertEquals("{\"answered\":0,\"forwarded\":0,\"failed\":0}", dns.path("queries").toString());
        assertNull(mesh.dnsResponder(), "a responder without phase two");
    }

    /** An unusable pool stops phase two alone: phase one's rules stay in force, domain rules do not. */
    @Test
    void anUnusablePoolStopsPhaseTwoAlone() {
        fakeIpCidr = "198.18.0.0/25";
        newMesh().applyRules(rules());

        JsonNode consumer = consumerStatus();
        assertFalse(consumer.path("dns").path("active").asBoolean());
        assertEquals(PeerEgressCodes.FAKE_IP_POOL_INVALID, consumer.path("dns").path("code").asText());
        assertEquals(PeerEgressCodes.RULE_DOMAIN_UNSUPPORTED, consumer.path("rules").get(0).path("code").asText());
        assertTrue(consumer.path("rules").get(1).path("inForce").asBoolean());
        assertNull(route(consumer, "198.18.0.0/25"));
        assertNull(mesh.fakeIpPool());
    }

    /** A pool over one of this device's own networks would shadow its hosts; checked at startup. */
    @Test
    void aPoolOverThisDevicesNetworkStopsPhaseTwo() {
        interfaces = List.of("198.18.5.0/24");
        newMesh().applyRules(rules());

        assertEquals(PeerEgressCodes.FAKE_IP_POOL_INVALID, consumerStatus().path("dns").path("code").asText());
        assertNull(route(consumerStatus(), POOL));
    }

    /**
     * A catalogue saying an egress no longer resolves names closes the flows to fake addresses it
     * was carrying, with a flow-purge naming the fake address; a new control session lets the
     * server number its catalogues from 1 again.
     */
    @Test
    void theCatalogueReachesTheConsumerAndPurgesWhatItNoLongerAllows() {
        newMesh().applyRules(rules());
        mesh.applyEgressCatalog(catalogue(5, true));
        String fake = mesh.fakeIpPool().query("example.com").addressText();
        assertEquals("198.18.0.2", fake);

        clearFrames();
        assertTrue(mesh.handleOutbound(synTo(fake, 40000)));
        List<byte[]> sent = frames();
        assertEquals(2, sent.size(), "want a name-bind and the SYN");
        PeerEgressFrame.Control bind = control(sent.get(0));
        assertNotNull(bind, "the name-bind did not go first");
        assertEquals(PeerEgressFrame.CONTROL_NAME_BIND, bind.type());
        assertEquals(fake, bind.address());
        assertEquals("example.com", bind.name());

        clearFrames();
        mesh.applyEgressCatalog(catalogue(6, false));
        PeerEgressFrame.Control purge = frames().stream().map(PeerEgressPhaseTwoTests::control)
                .filter(message -> message != null && PeerEgressFrame.CONTROL_FLOW_PURGE.equals(message.type()))
                .findFirst().orElse(null);
        assertNotNull(purge, "no flow-purge reached the egress");
        assertEquals(List.of(fake + "/32"), purge.destinations());
        assertEquals(2L, sentTo.get(0)[0]);

        // Same session: an older catalogue is ignored.
        mesh.applyEgressCatalog(catalogue(1, true));
        assertEquals(List.of(), mesh.domainCapableEgresses());
        mesh.newControlSession();
        mesh.applyEgressCatalog(catalogue(1, true));
        assertEquals(List.of(2L), mesh.domainCapableEgresses());
    }

    /** The control connection hands egress-catalog to the plane, and a login starts a new session. */
    @Test
    void theControlConnectionDeliversTheCatalogue() throws Exception {
        String previousHome = System.getProperty("user.home");
        System.setProperty("user.home", directory.toString());
        PeerMeshClient client = null;
        try {
            client = new PeerMeshClient(new ClientAuthLoginResponse.PeerMeshConfig(), (target, payload) -> {
            });
            // Delivered even though the mesh is not running yet: catalogues are pushed on change only.
            client.handleControlMessage(catalogue(3, true));
            assertEquals(List.of(2L), client.egressPlane().domainCapableEgresses());
            client.handleControlMessage(catalogue(1, false));
            assertEquals(List.of(2L), client.egressPlane().domainCapableEgresses(), "an older catalogue was taken");
            client.onControlSession();
            client.handleControlMessage(catalogue(1, false));
            assertEquals(List.of(), client.egressPlane().domainCapableEgresses());
        } finally {
            if (client != null) {
                client.close();
            }
            if (previousHome == null) {
                System.clearProperty("user.home");
            } else {
                System.setProperty("user.home", previousHome);
            }
        }
    }
}
