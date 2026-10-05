package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * What a consumer makes of an egress its rules name, bound to
 * {@code protocol/test-vectors/peer-egress-standing-v1.json} (protocol/spec/peer-egress.md,
 * "能力不支持").
 *
 * <p>Every case goes through the real consumer: the catalogue is a real {@code egress-catalog}
 * message read by the real reader, the egress's presence comes the way the mesh reports it, and
 * the packets are real IPv4 TCP and UDP written as an application would. What is checked is what
 * the consumer does with them -- the frames it sends and to whom, the reason it counts, what it
 * writes back to the TUN -- and the standing the status would report. Address rules and domain
 * rules (fake-IP steering) are both replayed, because the catalogue's verdict comes before the
 * domain capability check and has to come out the same for either kind of rule.
 */
class PeerEgressStandingVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long EPOCH = 1_800_000_000_000L;
    private static final String LOCAL = "100.96.0.2";
    private static final long EGRESS = 2L;
    /** Listed in every catalogue the cases build, so "not listed" never means "empty catalogue". */
    private static final long OTHER_EGRESS = 9L;
    private static final String POOL = "198.18.0.0/24";

    private record Sent(long egress, byte[] frame) {
    }

    static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve("peer-egress-standing-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-standing-v1.json");
    }

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertNotNull(value, dotted + " did not parse");
        return value;
    }

    private static PeerEgressRule rule(String match, long egress) {
        PeerEgressRule created = new PeerEgressRule();
        created.setMatch(match);
        created.setAction(PeerEgressRule.ACTION_EGRESS);
        created.setEgressClientId(egress);
        return created;
    }

    private static byte[] syn(String destination, int sourcePort) {
        return PeerEgressSegment.build(new PeerEgressSegment.Segment(address(LOCAL), address(destination),
                sourcePort, 443, 1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]));
    }

    private static byte[] datagram(String destination, int sourcePort) {
        return PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(address(LOCAL), address(destination),
                sourcePort, 443, "hello".getBytes(StandardCharsets.US_ASCII)));
    }

    /**
     * The catalogue a case describes, as the server would push it: egress 2's entry when the case
     * lists it, with the egressVersion the case gives or none, beside an entry for another egress.
     * Every entry says it resolves names, so for a domain rule only the standing can refuse.
     */
    private static String catalogue(JsonNode testCase, long revision) {
        ObjectNode message = MAPPER.createObjectNode();
        message.put("type", "egress-catalog");
        message.put("revision", revision);
        ArrayNode egresses = message.putArray("egresses");
        ObjectNode other = egresses.addObject();
        other.put("clientId", OTHER_EGRESS);
        other.put("online", true);
        other.put("domainTargetCapable", true);
        other.put("egressVersion", 1);
        if (testCase.path("listed").asBoolean()) {
            ObjectNode entry = egresses.addObject();
            entry.put("clientId", EGRESS);
            entry.put("online", testCase.path("online").asBoolean());
            entry.put("domainTargetCapable", true);
            if (testCase.has("egressVersion")) {
                entry.set("egressVersion", testCase.path("egressVersion"));
            }
        }
        return message.toString();
    }

    /**
     * The reader as the case leaves it. Without a catalogue this session, the previous session's
     * one stays known -- listing the egress, able to resolve names -- which is what keeps the
     * domain variant of the unknown case about the standing alone: a catalogue that stays is not
     * one received.
     */
    private static PeerEgressCatalog catalogFor(JsonNode testCase) {
        PeerEgressCatalog catalog = new PeerEgressCatalog();
        catalog.newSession(EPOCH);
        if (testCase.path("catalogReceived").asBoolean()) {
            assertTrue(catalog.read(catalogue(testCase, 1)), testCase.path("name").asText() + ": catalogue refused");
        } else {
            ObjectNode earlier = MAPPER.createObjectNode().put("listed", true).put("online", true);
            assertTrue(catalog.read(catalogue(earlier, 7)));
            catalog.newSession(EPOCH);
        }
        return catalog;
    }

    @Test
    void theWaitIsTheVectors() throws IOException {
        assertEquals(vector().path("catalogWaitSeconds").asLong() * 1000L, PeerEgressCatalog.WAIT_MILLIS);
    }

    /** The reference's standing function, case by case, before any packet is involved. */
    @Test
    void standingsAsTheSharedVectorSays() throws IOException {
        JsonNode cases = vector().path("cases");
        assertFalse(cases.isEmpty(), "no standing cases");
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            Long version = testCase.has("egressVersion") ? testCase.path("egressVersion").asLong() : null;
            PeerEgressCatalog.Standing standing = PeerEgressCatalog.Standing.of(
                    testCase.path("catalogReceived").asBoolean(), testCase.path("listed").asBoolean(), version);
            assertEquals(testCase.path("standing").asText(), standing.wireName(), name);
            assertEquals(testCase.path("standing").asText(), catalogFor(testCase).snapshot().standing(EGRESS).wireName(),
                    name + ": read from the catalogue");
        }
    }

    @Test
    void addressRulesDecideAsTheSharedVectorSays() throws IOException {
        for (JsonNode testCase : vector().path("cases")) {
            replay(testCase, false);
        }
    }

    @Test
    void domainRulesDecideAsTheSharedVectorSays() throws IOException {
        for (JsonNode testCase : vector().path("cases")) {
            replay(testCase, true);
        }
    }

    private void replay(JsonNode testCase, boolean domain) {
        String name = testCase.path("name").asText() + (domain ? " (domain rule)" : " (address rule)");
        List<Sent> sent = new ArrayList<>();
        List<byte[]> toTun = new ArrayList<>();
        PeerEgressConsumer consumer = new PeerEgressConsumer((egress, frame) -> {
            sent.add(new Sent(egress, frame.clone()));
            return true;
        }, packet -> toTun.add(packet.clone()));
        PeerEgressFakeIpPool pool = domain ? new PeerEgressFakeIpPool(Ipv4Cidr.parse(POOL), () -> EPOCH) : null;
        consumer.configure(List.of(domain ? rule("example.com", EGRESS) : rule("203.0.113.0/24", EGRESS)),
                PeerEgressRules.DEFAULT_MESH_CIDR, LOCAL, pool, EPOCH);
        consumer.setCatalog(catalogFor(testCase).snapshot(), EPOCH);
        consumer.setEgressOnline(EGRESS, testCase.path("online").asBoolean(), EPOCH);
        String destination = domain ? pool.query("example.com", EPOCH).addressText() : "203.0.113.10";

        assertEquals(testCase.path("standing").asText(),
                consumer.statusSnapshot(EPOCH).standings().get(EGRESS), name + ": standing");

        JsonNode blocked = testCase.path("blocked");
        int sourcePort = 40000;
        for (String protocol : List.of("tcp", "udp")) {
            byte[] packet = "tcp".equals(protocol) ? syn(destination, sourcePort) : datagram(destination, sourcePort);
            sourcePort++;
            String where = name + " " + protocol;
            sent.clear();
            toTun.clear();
            Map<String, Long> before = new TreeMap<>(consumer.blockedCounts());
            PeerEgressConsumer.Outcome outcome = consumer.handleOutbound(packet, EPOCH + 1);
            Map<String, Long> after = new TreeMap<>(consumer.blockedCounts());
            if (blocked.isNull()) {
                assertEquals(PeerEgressConsumer.Outcome.FORWARDED, outcome, where);
                assertEquals(before, after, where + ": a forwarded packet was counted as blocked");
                assertTrue(toTun.isEmpty(), where + ": a forwarded packet was answered locally");
                // A domain rule's first packet carries the name ahead of it.
                assertEquals(domain ? 2 : 1, sent.size(), where + ": frames sent");
                for (Sent frame : sent) {
                    assertEquals(EGRESS, frame.egress(), where + ": sent to the wrong egress");
                }
                PeerEgressFrame.Decoded ip = PeerEgressFrame.parse(sent.get(sent.size() - 1).frame());
                assertTrue(ip.accepted(), where);
                assertEquals(PeerEgressFrame.TYPE_IP_PACKET, ip.type(), where);
                assertArrayEquals(packet, ip.body(), where + ": the packet was not sent as written");
            } else {
                String reason = blocked.asText();
                assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS, outcome, where);
                assertTrue(sent.isEmpty(), where + ": a blocked packet was sent");
                Map<String, Long> want = new TreeMap<>(before);
                want.merge(reason, 1L, Long::sum);
                assertEquals(want, after, where + ": counted");
                // Answered exactly like egress-unavailable: a reset for TCP, host unreachable for UDP.
                byte[] answer = PeerEgressConsumer.failurePacket(packet, "tcp".equals(protocol)
                        ? PeerEgressSegment.IPV4_PROTOCOL_TCP : PeerEgressDatagram.IPV4_PROTOCOL_UDP);
                assertNotNull(answer, where);
                assertEquals(1, toTun.size(), where + ": not answered");
                assertArrayEquals(answer, toTun.get(0), where + ": answered unlike egress-unavailable");
            }
        }
    }

    /**
     * The domain capability check still runs, after the standing: an egress the catalogue offers
     * and that is online, but does not resolve names, takes no traffic for a name.
     */
    @Test
    void theDomainCheckComesAfterTheStanding() {
        List<byte[]> toTun = new ArrayList<>();
        PeerEgressConsumer consumer = new PeerEgressConsumer((egress, frame) -> true, toTun::add);
        PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse(POOL), () -> EPOCH);
        consumer.configure(List.of(rule("example.com", EGRESS)), PeerEgressRules.DEFAULT_MESH_CIDR, LOCAL, pool, EPOCH);
        consumer.setEgressOnline(EGRESS, true, EPOCH);
        PeerEgressCatalog catalog = new PeerEgressCatalog();
        catalog.newSession(EPOCH);
        assertTrue(catalog.read("{\"type\":\"egress-catalog\",\"revision\":1,\"egresses\":"
                + "[{\"clientId\":2,\"egressVersion\":1,\"domainTargetCapable\":false}]}"));
        consumer.setCatalog(catalog.snapshot(), EPOCH);
        String fake = pool.query("example.com", EPOCH).addressText();

        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS, consumer.handleOutbound(syn(fake, 40000), EPOCH));
        assertEquals(Map.of("egress-no-domain", 1L), consumer.blockedCounts());
        assertEquals(1, toTun.size(), "not answered");
    }
}
