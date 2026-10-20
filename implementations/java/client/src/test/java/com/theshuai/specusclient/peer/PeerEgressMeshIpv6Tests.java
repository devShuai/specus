package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressRule;
import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

/**
 * The IPv6 data plane as the mesh switches it on and off ({@code protocol/spec/peer-egress.md}, IPv6
 * 数据面, 消费端): it is on only while the platform, the MTU and the device all allow it, and a device
 * whose derived address could not be assigned keeps its IPv4 rules and routes while its IPv6 rules
 * are refused. The platform is stood in for, so these run on every platform the suite runs on.
 */
class PeerEgressMeshIpv6Tests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long START = 1_758_196_800_000L;
    private static final String DENIED =
            "the TUN's IPv6 address could not be assigned: RTNETLINK answers: Permission denied";

    @TempDir
    Path directory;

    private final Host host = new Host();
    private final PeerEgressDriftTests.TableCommander commander = new PeerEgressDriftTests.TableCommander();
    private PeerEgressMesh mesh;
    private ListAppender<ILoggingEvent> logs;
    private long now = START;

    /** A host whose device, peers and answers the test changes between ticks. */
    private final class Host implements PeerEgressMesh.Host {
        List<PeerEgressRule> rules = List.of();
        boolean deviceUp = true;
        PeerVirtualDevice.Ipv6Readiness ipv6 = PeerVirtualDevice.Ipv6Readiness.yes();
        List<String> bypass = List.of();
        Map<Long, Boolean> online = new HashMap<>();
        int sent;

        @Override
        public boolean sendToPeer(long peerId, byte[] frame) {
            sent++;
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

        @Override
        public boolean deviceReady() {
            return deviceUp;
        }

        @Override
        public String deviceStatus() {
            return deviceUp ? "ACTIVE" : "NOOP";
        }

        @Override
        public PeerVirtualDevice.Ipv6Readiness deviceIpv6() {
            return ipv6;
        }

        @Override
        public List<String> bypassHosts() {
            return bypass;
        }

        @Override
        public Map<Long, Boolean> egressAvailability() {
            return online;
        }
    }

    @BeforeEach
    void captureLogs() {
        logs = new ListAppender<>();
        logs.start();
        ((Logger) LoggerFactory.getLogger(PeerEgressMesh.class)).addAppender(logs);
    }

    @AfterEach
    void stop() {
        ((Logger) LoggerFactory.getLogger(PeerEgressMesh.class)).detachAppender(logs);
        if (mesh != null) {
            mesh.close();
        }
    }

    private static PeerEgressRule egressTo(String match, long target) {
        PeerEgressRule rule = new PeerEgressRule();
        rule.setMatch(match);
        rule.setAction(PeerEgressRule.ACTION_EGRESS);
        rule.setEgressClientId(target);
        return rule;
    }

    private PeerEgressMesh newMesh(PeerEgressRule... rules) {
        host.rules = List.of(rules);
        mesh = new PeerEgressMesh(host, (protocol, target, port, timeoutMs) -> {
            throw new IOException("nothing is dialled in this test");
        }, commander, name -> {
            throw new UnknownHostException(name);
        });
        // Stands in for the platform and the MTU; the device must still carry IPv6.
        mesh.ipv6Platform = true;
        return mesh;
    }

    private JsonNode consumerSection() {
        return MAPPER.valueToTree(mesh.status()).path("consumer");
    }

    private static byte[] syn6(String source, String destination) {
        return PeerEgressSegment.build(new PeerEgressSegment.Segment(0, 0, 40000, 443, 1, 0,
                PeerEgressSegment.FLAG_SYN, 65535, 0, new byte[0],
                PeerEgressIpv6Harness.address6(source), PeerEgressIpv6Harness.address6(destination)));
    }

    private static String local6() {
        return PeerEgressIpv6Packet.deviceAddress("100.96.0.1").format();
    }

    private long logged(String text) {
        return logs.list.stream().filter(event -> event.getFormattedMessage().contains(text)).count();
    }

    /**
     * A device whose derived IPv6 address could not be assigned has no IPv6 data plane: its IPv6
     * rules report EGRESS_RULE_IPV6_UNSUPPORTED, nothing IPv6 is planned, and the IPv4 routes are
     * installed and stay installed -- an IPv6 install that would fail cannot roll them back. Said once
     * in the log. When the device carries IPv6 again the next reconcile puts the IPv6 rules in force,
     * and when it stops the IPv6 routes go and the IPv4 ones stay.
     */
    @Test
    void withoutTheTunsIpv6AddressIpv4StaysAndIpv6IsRefused() {
        newMesh(egressTo("203.0.113.0/24", 2L), egressTo("2001:db8:1::/48", 2L));
        host.ipv6 = PeerVirtualDevice.Ipv6Readiness.no(DENIED);
        host.bypass = List.of("https://[2001:db8:1::443]:8443");
        // Were an IPv6 route attempted it would fail, and the failure would take the IPv4 route with it.
        commander.installErr.put("2001:db8:1::/48", new IOException("ip -6 route add failed: IPv6 is disabled"));

        mesh.reconcile(host.rules, now);
        now += PeerEgressRoutePlanner.RETRY_AFTER_MILLIS;
        mesh.reconcile(host.rules, now);
        assertTrue(commander.installLog.contains("203.0.113.0/24"), "installed " + commander.installLog);
        assertTrue(commander.installLog.stream().noneMatch(cidr -> cidr.contains(":")),
                "an IPv6 route was attempted without the address: " + commander.installLog);
        assertTrue(commander.table.containsKey("203.0.113.0/24"), "the IPv4 route did not stay installed");

        JsonNode section = consumerSection();
        JsonNode rules = section.path("rules");
        assertTrue(rules.get(0).path("inForce").asBoolean(), rules.toString());
        assertFalse(rules.get(1).path("inForce").asBoolean(), rules.toString());
        assertEquals(PeerEgressCodes.RULE_IPV6_UNSUPPORTED, rules.get(1).path("code").asText());
        assertFalse(section.has("routeError"), section.toString());
        assertFalse(section.path("rolledBack").asBoolean());
        for (JsonNode route : section.path("routes")) {
            assertFalse(route.path("cidr").asText().contains(":"), "an IPv6 route in the status: " + route);
        }
        assertEquals(1, logged("IPv6 rules not in force"), "the reason was not said exactly once");
        assertEquals(1, logged("Permission denied"));
        assertFalse(mesh.handleOutbound(syn6(local6(), "2001:db8:1::5")),
                "an IPv6 packet was claimed without the data plane");

        // The device recreated with its address: the next reconcile puts the IPv6 rule in force.
        commander.installErr.clear();
        host.ipv6 = PeerVirtualDevice.Ipv6Readiness.yes();
        now += 1_000;
        mesh.reconcile(host.rules, now);
        assertTrue(commander.table.containsKey("2001:db8:1::/48"),
                "the IPv6 route was not installed once the device carried IPv6: " + commander.installLog);
        assertTrue(commander.installLog.contains("2001:db8:1::443/128"),
                "the IPv6 bypass was not installed: " + commander.installLog);
        assertNotEquals(PeerEgressCodes.RULE_IPV6_UNSUPPORTED, consumerSection().path("rules").get(1).path("code").asText());
        assertEquals(1, logged("IPv6 rules are in force"));

        // And losing it again takes the IPv6 routes out, the IPv4 one staying.
        host.ipv6 = PeerVirtualDevice.Ipv6Readiness.no("the TUN is closed");
        now += 1_000;
        mesh.reconcile(host.rules, now);
        assertFalse(commander.table.containsKey("2001:db8:1::/48"), "the IPv6 route stayed");
        assertFalse(commander.table.containsKey("2001:db8:1::443/128"), "the IPv6 bypass stayed");
        assertTrue(commander.table.containsKey("203.0.113.0/24"), "the IPv4 route went with the IPv6 one");
        assertEquals(2, logged("IPv6 rules not in force"));
    }

    /** Without the platform's data plane the same configuration routes no IPv6, and says nothing. */
    @Test
    void withoutThePlatformNoIpv6IsRouted() {
        newMesh(egressTo("2001:db8:1::/48", 2L));
        mesh.ipv6Platform = false;
        host.bypass = List.of("https://[2001:db8:1::443]:8443");
        mesh.reconcile(host.rules, now);
        assertTrue(commander.installLog.isEmpty(), "installed " + commander.installLog);
        JsonNode rules = consumerSection().path("rules");
        assertEquals(1, rules.size());
        assertEquals(PeerEgressCodes.RULE_IPV6_UNSUPPORTED, rules.get(0).path("code").asText());
        assertEquals(0, logged("IPv6 rules not in force"), "a platform without IPv6 was reported as a fault");
    }

    /**
     * The status says which rule waits on an egress that does not take IPv6, and counts the new
     * reasons under their own names.
     */
    @Test
    void theStatusNamesTheIpv6Refusals() {
        newMesh(egressTo("2001:db8:1::/48", 2L));
        host.online.put(2L, true);
        mesh.reconcile(host.rules, now);
        assertTrue(commander.installLog.contains("2001:db8:1::/48"), "installed " + commander.installLog);

        assertTrue(mesh.handleOutbound(syn6(local6(), "2001:db8:1::5")));
        assertTrue(mesh.handleOutbound(syn6("2001:db8:ff::5", "2001:db8:1::5")));
        // The system's own chatter is not counted, and not claimed as traffic either.
        assertTrue(mesh.handleOutbound(syn6("fe80::1", "2001:db8:1::5")));

        JsonNode section = consumerSection();
        JsonNode rules = section.path("rules");
        assertFalse(rules.get(0).path("inForce").asBoolean());
        assertEquals(PeerEgressCodes.RULE_EGRESS_NO_IPV6, rules.get(0).path("code").asText());
        assertTrue(section.path("peers").isEmpty(), "a rule out of force contributed a peer: " + section.path("peers"));
        assertEquals(1, section.path("blocked").path("egress-no-ipv6").asLong());
        assertEquals(1, section.path("blocked").path("ipv6-source-not-mesh").asLong());
        assertEquals(2, section.path("blocked").size(), section.path("blocked").toString());
        assertEquals(0, host.sent, "something was sent to an egress that does not take IPv6");

        // The catalogue saying it does puts the rule in force and lets the packet go.
        mesh.newControlSession();
        mesh.applyEgressCatalog("{\"type\":\"egress-catalog\",\"revision\":1,\"egresses\":["
                + "{\"clientId\":2,\"egressVersion\":1,\"ipv6PacketCapable\":true}]}");
        assertTrue(consumerSection().path("rules").get(0).path("inForce").asBoolean());
        assertTrue(mesh.handleOutbound(syn6(local6(), "2001:db8:1::6")));
        assertEquals(1, host.sent);
    }

    /** A device that is not up, or one that does not answer for IPv6, carries no IPv6. */
    @Test
    void onlyAnUpDeviceWithItsAddressCarriesIpv6() {
        newMesh();
        assertTrue(mesh.ipv6State().ready());
        host.deviceUp = false;
        PeerVirtualDevice.Ipv6Readiness down = mesh.ipv6State();
        assertFalse(down.ready());
        assertEquals("the virtual device is NOOP", down.reason());
        host.deviceUp = true;
        host.ipv6 = new NoopPeerVirtualDevice().ipv6Readiness();
        assertFalse(mesh.ipv6State().ready());
        mesh.ipv6Platform = null;
        assertEquals(PeerEgressRouteCommanders.platformCarriesIpv6() ? "the virtual device carries no IPv6"
                : "this platform or peerMeshMtu has no IPv6 data plane", mesh.ipv6State().reason());
    }
}
