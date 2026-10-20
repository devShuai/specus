package com.theshuai.specusclient.peer;

import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.EPOCH;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.address6;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv6Cidr;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressDns;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The consumer side of the IPv6 data plane against {@code protocol/test-vectors/peer-egress-ipv6-v1.json}:
 * ruleValidation, consumerOutbound, returnPath and failure, and the rules vector's {@code ipv6}
 * section run through the consumer's own steering. The data plane is switched on in the consumer
 * directly, so these run on every platform the suite runs on.
 */
class PeerEgressConsumerIpv6Tests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The rule every packet in the vector's consumer sections falls under. */
    private static PeerEgressRule vectorRule() {
        return rule("2001:db8:1::/48", PeerEgressRule.ACTION_EGRESS, 2L);
    }

    private static PeerEgressRule rule(String match, String action, Long egress) {
        PeerEgressRule rule = new PeerEgressRule();
        rule.setMatch(match);
        rule.setAction(action);
        rule.setEgressClientId(egress);
        return rule;
    }

    /** A consumer with the IPv6 data plane, recording what it sends and what it writes to the TUN. */
    private static final class Harness {
        final List<Long> sentTo = new ArrayList<>();
        final List<byte[]> sent = new ArrayList<>();
        final List<byte[]> toTun = new ArrayList<>();
        final PeerEgressConsumer consumer;

        /** Egress 2 listed by the catalogue, online or not, taking IPv6 packets or not. */
        Harness(String meshIpv4, List<PeerEgressRule> rules, boolean online, boolean capable) {
            consumer = new PeerEgressConsumer((egress, frame) -> {
                sentTo.add(egress);
                sent.add(frame.clone());
                return true;
            }, packet -> toTun.add(packet.clone()));
            consumer.configure(rules, PeerEgressRules.DEFAULT_MESH_CIDR, meshIpv4, null, null, true, EPOCH);
            consumer.setCatalog(new PeerEgressCatalog.Snapshot(true, Set.of(2L), Map.of(2L, 1L), Set.of(),
                    capable ? Set.of(2L) : Set.of()), EPOCH);
            consumer.setEgressOnline(2L, online, EPOCH);
        }

        Map<String, Long> blocked() {
            return consumer.blockedCounts();
        }
    }

    private static byte[] hex(String text) {
        return HexFormat.of().parseHex(text);
    }

    private static boolean covers(String match, byte[] packet) {
        Ipv6Cidr cidr = Ipv6Cidr.parse(match);
        return cidr != null && cidr.contains(PeerEgressIpv6Packet.Address.read(packet, 24).halves());
    }

    @Test
    void ruleValidationMatchesSharedVector() throws IOException {
        JsonNode vector = PeerEgressIpv6Harness.vector();
        JsonNode cases = vector.path("ruleValidation").path("cases");
        assertFalse(cases.isEmpty(), "the IPv6 vector carried no ruleValidation cases");
        byte[] toARule = hex(vector.path("consumerOutbound").path("cases").get(0).path("packetHex").asText());
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            PeerEgressRule rule = rule(testCase.path("rule").path("match").asText(),
                    testCase.path("rule").path("action").asText(), testCase.path("rule").path("egressClientId").asLong());
            String want = testCase.path("code").isNull() ? null : testCase.path("code").asText();
            boolean online = testCase.path("egressOnline").asBoolean();
            boolean capable = testCase.path("egressIpv6PacketCapable").asBoolean();
            assertEquals(want, PeerEgressDns.ruleStatus(rule, PeerEgressRules.DEFAULT_MESH_CIDR, null, true,
                    egress -> online, egress -> false, egress -> capable), name);

            // The same answer from the status a running consumer publishes.
            Harness harness = new Harness("100.96.0.1", List.of(rule), online, capable);
            JsonNode status = MAPPER.valueToTree(PeerEgressStatus.section(harness.consumer.statusSnapshot(EPOCH),
                    List.of(), PeerEgressStatus.ApplyOutcome.none(), null));
            JsonNode entry = status.path("consumer").path("rules").get(0);
            assertEquals(want == null, entry.path("inForce").asBoolean(), name + " inForce");
            assertEquals(want == null ? "" : want, entry.path("code").asText(""), name + " status code");

            // And what the traffic does: a rule out of force for its egress still claims its
            // destination, and blocks it under the egress's reason rather than letting it out.
            if (PeerEgressCodes.RULE_MESH_OVERLAP.equals(want) || !covers(rule.getMatch(), toARule)) {
                continue;
            }
            harness.consumer.handleOutbound(toARule, EPOCH);
            if (!online) {
                assertEquals(Map.of("egress-unavailable", 1L), harness.blocked(), name);
            } else if (PeerEgressCodes.RULE_EGRESS_NO_IPV6.equals(want)) {
                assertEquals(Map.of("egress-no-ipv6", 1L), harness.blocked(), name);
                assertTrue(harness.sent.isEmpty(), name + ": sent to an egress that does not take IPv6");
            } else {
                assertEquals(1, harness.sent.size(), name + ": not forwarded");
                assertTrue(harness.blocked().isEmpty(), name + ": blocked " + harness.blocked());
            }
        }
    }

    @Test
    void consumerOutboundMatchesSharedVector() throws IOException {
        JsonNode section = PeerEgressIpv6Harness.vector().path("consumerOutbound");
        String mesh = section.path("consumerMeshIpv4").asText();
        assertFalse(section.path("cases").isEmpty(), "no consumerOutbound cases");
        for (JsonNode testCase : section.path("cases")) {
            String name = testCase.path("name").asText();
            Harness harness = new Harness(mesh, List.of(vectorRule()), true, true);
            int mtu = testCase.path("effectiveMtu").asInt();
            List<Long> asked = new ArrayList<>();
            harness.consumer.setPathMtu(egress -> {
                asked.add(egress);
                return mtu;
            });
            byte[] packet = hex(testCase.path("packetHex").asText());
            PeerEgressConsumer.Outcome outcome = harness.consumer.handleOutbound(packet, EPOCH);
            assertTrue(harness.toTun.isEmpty(), name + ": answered into the TUN");
            assertTrue(asked.stream().allMatch(egress -> egress == 2L), name + ": path MTU asked of " + asked);
            switch (testCase.path("expect").asText()) {
                case "forward" -> {
                    assertEquals(PeerEgressConsumer.Outcome.FORWARDED, outcome, name);
                    assertEquals(List.of(2L), harness.sentTo, name);
                    PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(harness.sent.get(0), true);
                    assertTrue(frame.accepted(), name + ": " + frame.code());
                    assertEquals(PeerEgressFrame.TYPE_IP_PACKET, frame.type(), name);
                    assertFalse(frame.hop(), name + ": hop set");
                    assertArrayEquals(packet, frame.body(), name + ": the packet did not go as it was");
                    assertTrue(harness.blocked().isEmpty(), name + ": blocked " + harness.blocked());
                }
                case "drop-silently" -> {
                    assertEquals(PeerEgressConsumer.Outcome.IGNORED, outcome, name);
                    assertTrue(harness.sent.isEmpty() && harness.blocked().isEmpty(),
                            name + ": sent " + harness.sent.size() + " blocked " + harness.blocked());
                }
                default -> {
                    assertTrue(harness.sent.isEmpty(), name + ": sent");
                    assertEquals(Map.of(testCase.path("expect").asText(), 1L), harness.blocked(), name);
                }
            }
        }
    }

    @Test
    void returnPathMatchesSharedVector() throws IOException {
        JsonNode vector = PeerEgressIpv6Harness.vector();
        JsonNode section = vector.path("returnPath");
        String mesh = section.path("consumerMeshIpv4").asText();
        // The flow the replies belong to is the vector's own outbound packet: the same five-tuple,
        // mirrored.
        byte[] opening = hex(vector.path("consumerOutbound").path("cases").get(0).path("packetHex").asText());
        assertFalse(section.path("cases").isEmpty(), "no returnPath cases");
        for (JsonNode testCase : section.path("cases")) {
            String name = testCase.path("name").asText();
            Harness harness = new Harness(mesh, List.of(vectorRule()), true, true);
            if (testCase.path("liveFlow").asBoolean()) {
                assertEquals(PeerEgressConsumer.Outcome.FORWARDED, harness.consumer.handleOutbound(opening, EPOCH),
                        name + ": the flow did not open");
            }
            byte[] packet = hex(testCase.path("packetHex").asText());
            boolean claimed = harness.consumer.handleInbound(PeerEgressIpv6Harness.frameFor(packet), 2L, EPOCH);
            switch (testCase.path("expect").asText()) {
                case "deliver" -> {
                    assertTrue(claimed, name);
                    assertEquals(1, harness.toTun.size(), name);
                    assertArrayEquals(packet, harness.toTun.get(0), name);
                    assertTrue(harness.blocked().isEmpty(), name + ": blocked " + harness.blocked());
                }
                case "not-for-consumer" -> {
                    assertFalse(claimed, name + ": claimed; it belongs to the egress role");
                    assertTrue(harness.toTun.isEmpty() && harness.blocked().isEmpty(), name);
                }
                default -> {
                    assertTrue(claimed, name);
                    assertTrue(harness.toTun.isEmpty(), name + ": delivered");
                    assertEquals(Map.of(testCase.path("expect").asText(), 1L), harness.blocked(), name);
                }
            }
        }

        // From the right five-tuple but another egress, a reply is not one this device asked for.
        Harness harness = new Harness(mesh, List.of(vectorRule()), true, true);
        harness.consumer.handleOutbound(opening, EPOCH);
        byte[] reply = hex(section.path("cases").get(0).path("packetHex").asText());
        assertTrue(harness.consumer.handleInbound(PeerEgressIpv6Harness.frameFor(reply), 3L, EPOCH));
        assertEquals(Map.of("return-no-flow", 1L), harness.blocked());
        assertTrue(harness.toTun.isEmpty());
    }

    /** Without the data plane the consumer leaves IPv6 alone in both directions, as before it existed. */
    @Test
    void ipv6IsNotClaimedWithoutTheDataPlane() throws IOException {
        JsonNode vector = PeerEgressIpv6Harness.vector();
        Harness harness = new Harness("100.96.0.1", List.of(vectorRule()), true, true);
        harness.consumer.configure(List.of(vectorRule()), PeerEgressRules.DEFAULT_MESH_CIDR, "100.96.0.1", null, null,
                false, EPOCH);
        assertFalse(harness.consumer.carriesIpv6());
        for (JsonNode testCase : vector.path("consumerOutbound").path("cases")) {
            assertEquals(PeerEgressConsumer.Outcome.NOT_MINE,
                    harness.consumer.handleOutbound(hex(testCase.path("packetHex").asText()), EPOCH),
                    testCase.path("name").asText());
        }
        byte[] reply = hex(vector.path("returnPath").path("cases").get(0).path("packetHex").asText());
        assertFalse(harness.consumer.handleInbound(PeerEgressIpv6Harness.frameFor(reply), 2L, EPOCH),
                "an IPv6 reply was claimed without the data plane");
        assertTrue(harness.blocked().isEmpty() && harness.sent.isEmpty() && harness.toTun.isEmpty());

        // And the status reads the IPv6 rule as the data plane it lacks.
        JsonNode status = MAPPER.valueToTree(PeerEgressStatus.section(harness.consumer.statusSnapshot(EPOCH),
                List.of(), PeerEgressStatus.ApplyOutcome.none(), null));
        assertEquals(PeerEgressCodes.RULE_IPV6_UNSUPPORTED, status.path("consumer").path("rules").get(0).path("code").asText());
    }

    /** Byte for byte: what goes back into the TUN when the egress a rule names is unavailable. */
    @Test
    void failureMatchesSharedVector() throws IOException {
        JsonNode failure = PeerEgressIpv6Harness.vector().path("failure");
        List<JsonNode> cases = new ArrayList<>();
        failure.path("resetOnPacket").path("cases").forEach(cases::add);
        failure.path("unreachableOnDatagram").path("cases").forEach(cases::add);
        assertTrue(cases.size() >= 4, "the failure vector carried " + cases.size() + " cases");
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            byte[] packet = hex(testCase.path("packetHex").asText());
            String want = testCase.path("expect").path("packetHex").asText();
            byte[] answer = PeerEgressConsumer.failurePacket6(packet, packet[6] & 0xff);
            assertNotNull(answer, name);
            assertEquals(want, HexFormat.of().formatHex(answer), name);
            assertTrue(answer.length <= PeerEgressIpv6Packet.MINIMUM_MTU, name + ": past the IPv6 minimum MTU");

            // Through the data plane: the rule's egress is offline.
            Harness harness = new Harness("100.96.0.1", List.of(vectorRule()), false, true);
            assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS, harness.consumer.handleOutbound(packet, EPOCH), name);
            assertEquals(1, harness.toTun.size(), name);
            assertEquals(want, HexFormat.of().formatHex(harness.toTun.get(0)), name);
        }
        // Nothing an application could act on is answered: not IPv6, or not TCP or UDP.
        assertNull(PeerEgressIpv6Packet.icmpAddressUnreachable(new byte[] {0x45, 0, 0, 20}));
        assertNull(PeerEgressConsumer.failurePacket6(hex(cases.get(0).path("packetHex").asText()), 58));
    }

    /**
     * resetOnPurge in IPv6: a flow the consumer closes itself is reset from what it remembered, by
     * the same rule as IPv4, and the purge names the destination as a /128.
     */
    @Test
    void purgeResetsTheFlow() {
        PeerEgressIpv6Packet.Address local = PeerEgressIpv6Packet.deviceAddress("100.96.0.1");
        PeerEgressIpv6Packet.Address remote = address6("2001:db8:1::c8");
        byte[] data = PeerEgressSegment.build(new PeerEgressSegment.Segment(0, 0, 40000, 443, 5000, 9000,
                PeerEgressSegment.FLAG_ACK | PeerEgressSegment.FLAG_PSH, 65535, 0,
                "GET /".getBytes(StandardCharsets.US_ASCII), local, remote));

        Harness harness = new Harness("100.96.0.1", List.of(vectorRule()), true, true);
        assertEquals(PeerEgressConsumer.Outcome.FORWARDED, harness.consumer.handleOutbound(data, EPOCH));
        Map<Long, List<String>> purge = harness.consumer.setEgressOnline(2L, false, EPOCH);
        assertEquals(Map.of(2L, List.of("2001:db8:1::c8/128")), purge);
        assertEquals(1, harness.toTun.size(), "resets written");
        byte[] written = harness.toTun.get(0);
        PeerEgressSegment.Segment reset = PeerEgressIpv6Packet.parseSegment(written);
        assertNotNull(reset, "the reset does not read as IPv6 TCP");
        assertEquals(remote, reset.sourceIp6());
        assertEquals(local, reset.destinationIp6());
        assertEquals(443, reset.sourcePort());
        assertEquals(40000, reset.destinationPort());
        assertEquals(PeerEgressSegment.FLAG_RST | PeerEgressSegment.FLAG_ACK, reset.flags());
        assertEquals(9000, reset.seq());
        assertEquals(5005, reset.ack());
        assertEquals(0, reset.window());
        assertEquals(PeerEgressIpv6Packet.HOP_LIMIT, written[7] & 0xff);
        assertEquals(0, written[1]);

        // The catalogue no longer saying the egress takes IPv6 packets closes the flow as well.
        harness = new Harness("100.96.0.1", List.of(vectorRule()), true, true);
        harness.consumer.handleOutbound(data, EPOCH);
        purge = harness.consumer.setCatalog(new PeerEgressCatalog.Snapshot(true, Set.of(2L), Map.of(2L, 1L), Set.of()),
                EPOCH);
        assertEquals(Map.of(2L, List.of("2001:db8:1::c8/128")), purge);
        assertEquals(0, harness.consumer.flowCount());

        // And so does the device ceasing to carry IPv6.
        harness = new Harness("100.96.0.1", List.of(vectorRule()), true, true);
        harness.consumer.handleOutbound(data, EPOCH);
        purge = harness.consumer.configure(List.of(vectorRule()), PeerEgressRules.DEFAULT_MESH_CIDR, "100.96.0.1",
                null, null, false, EPOCH);
        assertEquals(Map.of(2L, List.of("2001:db8:1::c8/128")), purge);
        assertEquals(0, harness.consumer.flowCount());
    }

    /** A flow-reject for an IPv6 flow names it in IPv6, and resets and forgets it. */
    @Test
    void flowRejectClosesTheFlow() {
        PeerEgressIpv6Packet.Address local = PeerEgressIpv6Packet.deviceAddress("100.96.0.1");
        PeerEgressIpv6Packet.Address remote = address6("2001:db8:1::c8");
        Harness harness = new Harness("100.96.0.1", List.of(vectorRule()), true, true);
        harness.consumer.handleOutbound(PeerEgressSegment.build(new PeerEgressSegment.Segment(0, 0, 40000, 443,
                5000, 9000, PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0], local, remote)), EPOCH);
        // A family mix names no flow.
        byte[] mixed = PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false, PeerEgressFrame.encodeControl(
                PeerEgressFrame.Control.flowReject("tcp", "100.96.0.1", 40000, remote.format(), 443,
                        PeerEgressCodes.DEST_DENIED)));
        assertTrue(harness.consumer.handleInbound(mixed, 2L, EPOCH));
        assertEquals(1, harness.consumer.flowCount(), "a family mix closed the flow");

        byte[] reject = PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false, PeerEgressFrame.encodeControl(
                PeerEgressFrame.Control.flowReject("tcp", local.format(), 40000, remote.format(), 443,
                        PeerEgressCodes.DEST_DENIED)));
        assertTrue(harness.consumer.handleInbound(reject, 2L, EPOCH), "the flow-reject was not claimed");
        assertEquals(0, harness.consumer.flowCount());
        assertEquals(1, harness.toTun.size());
        assertEquals(Map.of("rejected-egress_dest_denied", 1L), harness.blocked());
    }

    /**
     * The rule set of the rules vector's ipv6 section, run through the consumer with the data plane:
     * what each IPv6 destination's packet does is what the vector says the rules decide.
     */
    @Test
    void steersByTheRulesVector() throws IOException {
        JsonNode section = rulesVector().path("ipv6");
        List<PeerEgressRule> rules = new ArrayList<>();
        for (JsonNode node : section.path("rules")) {
            rules.add(MAPPER.treeToValue(node, PeerEgressRule.class));
        }
        assertFalse(rules.isEmpty());
        int checked = 0;
        for (JsonNode testCase : section.path("cases")) {
            PeerEgressIpv6Packet.Address destination = PeerEgressIpv6Packet.Address.parse(testCase.path("destination").asText());
            if (destination == null) {
                continue;
            }
            String name = testCase.path("destination").asText();
            JsonNode expect = testCase.path("expect");
            long egress = expect.path("egressClientId").asLong(0);
            Harness harness = new Harness("100.96.0.1", rules, true, true);
            if (egress != 0) {
                harness.consumer.setCatalog(new PeerEgressCatalog.Snapshot(true, Set.of(egress), Map.of(egress, 1L),
                        Set.of(), Set.of(egress)), EPOCH);
                harness.consumer.setEgressOnline(egress, true, EPOCH);
            }
            PeerEgressConsumer.Outcome outcome = harness.consumer.handleOutbound(PeerEgressSegment.build(
                    new PeerEgressSegment.Segment(0, 0, 40000, 443, 1, 0, PeerEgressSegment.FLAG_SYN, 65535, 0,
                            new byte[0], PeerEgressIpv6Packet.deviceAddress("100.96.0.1"), destination)), EPOCH);
            switch (expect.path("action").asText()) {
                case PeerEgressRule.ACTION_EGRESS -> {
                    assertEquals(PeerEgressConsumer.Outcome.FORWARDED, outcome, name);
                    assertEquals(List.of(egress), harness.sentTo, name);
                }
                case PeerEgressRule.ACTION_BLOCK -> assertEquals(PeerEgressConsumer.Outcome.BLOCKED_BY_RULE, outcome, name);
                default -> {
                    // Direct, or a mesh destination the data plane refuses before the rules.
                    assertTrue(outcome == PeerEgressConsumer.Outcome.NOT_MINE
                            || outcome == PeerEgressConsumer.Outcome.BLOCKED_IPV6, name + ": " + outcome);
                    assertTrue(harness.sent.isEmpty(), name);
                }
            }
            checked++;
        }
        assertTrue(checked > 0, "no IPv6 destination in the rules vector");
    }

    /** The link-local and multicast tests are the prefixes they claim, and nothing either side. */
    @Test
    void theSystemsOwnTrafficIsToldApartByItsPrefixes() throws IOException {
        Harness harness = new Harness("100.96.0.1", List.of(vectorRule()), true, true);
        PeerEgressIpv6Packet.Address mine = PeerEgressIpv6Packet.deviceAddress("100.96.0.1");
        for (String[] pair : new String[][] {
                {"febf:ffff::1", "2001:db8:1::1", "ignored"},
                {"fec0::1", "2001:db8:1::1", "blocked-ipv6"},
                {mine.format(), "ff02::1", "ignored"},
                {mine.format(), "feff::1", "not-mine"}}) {
            byte[] packet = PeerEgressSegment.build(new PeerEgressSegment.Segment(0, 0, 40000, 443, 1, 0,
                    PeerEgressSegment.FLAG_SYN, 65535, 0, new byte[0], address6(pair[0]), address6(pair[1])));
            assertEquals(pair[2], harness.consumer.handleOutbound(packet, EPOCH).toString(), pair[0] + " -> " + pair[1]);
        }
    }

    private static JsonNode rulesVector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve("peer-egress-rules-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-rules-v1.json");
    }
}
