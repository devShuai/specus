package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Binds when the consumer forgets a flow to {@code peer-egress-consumer-flows-v1.json}.
 *
 * <p>Every event goes through the real consumer: packets out of the TUN through
 * {@link PeerEgressConsumer#handleOutbound}, replies as SPEG1 frames through
 * {@link PeerEgressConsumer#handleInbound}, and the count through the status snapshot an operator
 * reads. A client that forgot a flow sooner than the others would refuse replies they accept; one
 * that forgot later would hold memory the others release.
 */
class PeerEgressConsumerFlowVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long EPOCH = 1_800_000_000_000L;
    private static final long EGRESS = 2L;

    private static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors")
                    .resolve("peer-egress-consumer-flows-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-consumer-flows-v1.json");
    }

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertTrue(value != null, dotted + " did not parse");
        return value;
    }

    private static int protocolNumber(String name) {
        return switch (name) {
            case "tcp" -> PeerEgressSegment.IPV4_PROTOCOL_TCP;
            case "udp" -> PeerEgressDatagram.IPV4_PROTOCOL_UDP;
            default -> throw new IllegalArgumentException("unknown protocol " + name);
        };
    }

    /** The vector's flag letters. */
    private static int flagsOf(String letters) {
        int flags = 0;
        for (char letter : letters.toCharArray()) {
            flags |= switch (letter) {
                case 'S' -> PeerEgressSegment.FLAG_SYN;
                case 'A' -> PeerEgressSegment.FLAG_ACK;
                case 'F' -> PeerEgressSegment.FLAG_FIN;
                case 'R' -> PeerEgressSegment.FLAG_RST;
                default -> throw new IllegalArgumentException("unknown flag " + letter);
            };
        }
        return flags;
    }

    private static long at(JsonNode event) {
        return EPOCH + Math.round(event.path("at").asDouble() * 1000);
    }

    /** A consumer steering 203.0.113.0/24 to one online egress, and what it wrote to its TUN. */
    private record Harness(PeerEgressConsumer consumer, List<byte[]> toTun, String local, int remote) {

        static Harness of(int capacity, String local) {
            List<byte[]> toTun = new ArrayList<>();
            PeerEgressConsumer consumer =
                    new PeerEgressConsumer((egress, frame) -> true, toTun::add, capacity);
            PeerEgressRule rule = new PeerEgressRule();
            rule.setMatch("203.0.113.0/24");
            rule.setAction(PeerEgressRule.ACTION_EGRESS);
            rule.setEgressClientId(EGRESS);
            consumer.configure(List.of(rule), PeerEgressRules.DEFAULT_MESH_CIDR, local, EPOCH);
            consumer.setEgressOnline(EGRESS, true, EPOCH);
            return new Harness(consumer, toTun, local, address("203.0.113.10"));
        }

        PeerEgressConsumer.Outcome out(int protocol, int port, int remotePort, int flags, long nowMs) {
            byte[] packet = protocol == PeerEgressSegment.IPV4_PROTOCOL_TCP
                    ? PeerEgressSegment.build(new PeerEgressSegment.Segment(address(local), remote,
                            port, remotePort, 1000, 1, flags, 65535, 0, new byte[0]))
                    : PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(address(local), remote,
                            port, remotePort, "query".getBytes(StandardCharsets.US_ASCII)));
            return consumer.handleOutbound(packet, nowMs);
        }

        /** Feeds one reply from the egress and says what became of it, in the vector's words. */
        String in(int protocol, int port, int remotePort, int flags, long nowMs) {
            byte[] packet = protocol == PeerEgressSegment.IPV4_PROTOCOL_TCP
                    ? PeerEgressSegment.build(new PeerEgressSegment.Segment(remote, address(local),
                            remotePort, port, 1, 1001, flags, 65535, 0, new byte[0]))
                    : PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(remote, address(local),
                            remotePort, port, "answer".getBytes(StandardCharsets.US_ASCII)));
            int written = toTun.size();
            long refused = consumer.blockedCounts().getOrDefault("return-no-flow", 0L);
            assertTrue(consumer.handleInbound(
                    PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false, packet), EGRESS, nowMs),
                    "a reply addressed to the consumer was not claimed");
            if (toTun.size() == written + 1) {
                return "delivered";
            }
            assertEquals(written, toTun.size(), "more than one packet reached the TUN");
            assertEquals(refused + 1, consumer.blockedCounts().getOrDefault("return-no-flow", 0L),
                    "a reply was neither delivered nor refused for want of a flow");
            return "return-no-flow";
        }

        boolean knows(int protocol, int port, int remotePort, long nowMs) {
            return consumer.remembers(
                    new PeerEgressFlowTable.Key(protocol, address(local), port, remote, remotePort), nowMs);
        }
    }

    @Test
    void timersMatchTheSharedVector() throws IOException {
        JsonNode document = vector();
        assertEquals(document.path("udpIdleSeconds").asLong() * 1000, PeerEgressConsumer.UDP_IDLE_MS);
        assertEquals(document.path("tcpIdleSeconds").asLong() * 1000, PeerEgressConsumer.TCP_IDLE_MS);
        assertEquals(document.path("tcpClosedLingerSeconds").asLong() * 1000,
                PeerEgressConsumer.TCP_CLOSED_LINGER_MS);
    }

    @Test
    void forgetsFlowsAsTheSharedVectorSays() throws IOException {
        JsonNode document = vector();
        String local = document.path("consumer").asText();
        String[] remote = document.path("remote").asText().split(":");
        assertEquals("203.0.113.10", remote[0], "the harness's rule does not cover the vector's remote");
        int remotePort = Integer.parseInt(remote[1]);
        JsonNode cases = document.path("cases");
        assertFalse(cases.isEmpty(), "no cases");

        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            Harness harness = Harness.of(testCase.path("capacity").asInt(), local);
            JsonNode events = testCase.path("events");
            JsonNode results = testCase.path("results");
            assertEquals(events.size(), results.size(), name + ": events and results differ in length");
            // The vector names a flow by its consumer port; the protocol is the one it went out with.
            Map<Integer, Integer> protocols = new HashMap<>();

            for (int index = 0; index < events.size(); index++) {
                JsonNode event = events.get(index);
                JsonNode expected = results.get(index);
                String where = name + " event " + index + " " + event;
                long nowMs = at(event);
                int flags = flagsOf(event.path("flags").asText(""));
                if (event.has("out")) {
                    int port = event.path("out").asInt();
                    int protocol = protocolNumber(event.path("protocol").asText());
                    protocols.put(port, protocol);
                    assertEquals(PeerEgressConsumer.Outcome.FORWARDED,
                            harness.out(protocol, port, remotePort, flags, nowMs), where);
                    assertEquals("forwarded", expected.asText(), where);
                } else if (event.has("in")) {
                    int port = event.path("in").asInt();
                    // A reply for a port that never went out carries TCP flags or none.
                    int protocol = protocols.getOrDefault(port, event.has("flags")
                            ? PeerEgressSegment.IPV4_PROTOCOL_TCP : PeerEgressDatagram.IPV4_PROTOCOL_UDP);
                    assertEquals(expected.asText(), harness.in(protocol, port, remotePort, flags, nowMs), where);
                } else if (event.has("known")) {
                    int port = event.path("known").asInt();
                    Integer protocol = protocols.get(port);
                    assertTrue(protocol != null, where + ": asks about a port that never went out");
                    assertEquals(expected.asBoolean(), harness.knows(protocol, port, remotePort, nowMs), where);
                } else {
                    assertEquals(expected.asInt(), harness.consumer().statusSnapshot(nowMs).flows(), where);
                }
            }
        }
    }

    /**
     * Forgetting is not only a matter of lookups: the entries have to leave memory, or the table is
     * bounded on paper only. Traffic on other flows is enough to sweep the lapsed ones out.
     */
    @Test
    void releasesLapsedFlowsWithoutAStatusRead() {
        Harness harness = Harness.of(PeerEgressConsumer.DEFAULT_FLOW_CAPACITY, "100.96.0.2");
        for (int port = 5000; port < 5100; port++) {
            harness.out(PeerEgressDatagram.IPV4_PROTOCOL_UDP, port, 443, 0, EPOCH);
        }
        assertEquals(100, harness.consumer().flowCount());

        harness.out(PeerEgressDatagram.IPV4_PROTOCOL_UDP, 6000, 443, 0, EPOCH + PeerEgressConsumer.UDP_IDLE_MS);

        assertEquals(1, harness.consumer().flowCount(), "lapsed flows are still held in memory");
    }

    /**
     * Two flows last seen in the same millisecond: the one registered first goes, even when the
     * other was the one seen longer ago within that millisecond.
     */
    @Test
    void evictsTheEarlierRegisteredOfTwoEquallyStaleFlows() {
        Harness harness = Harness.of(2, "100.96.0.2");
        int udp = PeerEgressDatagram.IPV4_PROTOCOL_UDP;
        harness.out(udp, 7001, 443, 0, EPOCH);
        harness.out(udp, 7002, 443, 0, EPOCH);
        assertEquals("delivered", harness.in(udp, 7001, 443, 0, EPOCH));

        harness.out(udp, 7003, 443, 0, EPOCH + 1);

        assertFalse(harness.knows(udp, 7001, 443, EPOCH + 1), "the later registered flow was kept");
        assertTrue(harness.knows(udp, 7002, 443, EPOCH + 1));
        assertTrue(harness.knows(udp, 7003, 443, EPOCH + 1));
    }

    /**
     * Only live flows fill the table. A flow that has lapsed makes room for a new one even when
     * nothing has swept it yet, rather than a live flow being evicted in its place.
     */
    @Test
    void aLapsedFlowMakesRoomBeforeALiveOneIsEvicted() {
        Harness harness = Harness.of(3, "100.96.0.2");
        int tcp = PeerEgressSegment.IPV4_PROTOCOL_TCP;
        int udp = PeerEgressDatagram.IPV4_PROTOCOL_UDP;
        // The oldest by last packet, and live for another two hours.
        harness.out(tcp, 6000, 443, PeerEgressSegment.FLAG_SYN, EPOCH);
        harness.out(udp, 5001, 443, 0, EPOCH + 200);
        harness.out(udp, 5002, 443, 0, EPOCH + 500);
        // A stray reply sweeps 5001 out, leaving 5002 as the next to lapse; a new flow fills the table.
        harness.in(udp, 5999, 443, 0, EPOCH + PeerEgressConsumer.UDP_IDLE_MS + 300);
        harness.out(udp, 5003, 443, 0, EPOCH + PeerEgressConsumer.UDP_IDLE_MS + 350);
        assertEquals(3, harness.consumer().flowCount());

        // 5002 has now lapsed, and too little time has passed for the periodic sweep to run again.
        harness.out(udp, 5004, 443, 0, EPOCH + PeerEgressConsumer.UDP_IDLE_MS + 600);

        long now = EPOCH + PeerEgressConsumer.UDP_IDLE_MS + 600;
        assertTrue(harness.knows(tcp, 6000, 443, now), "a live flow was evicted while a lapsed one held a place");
        assertTrue(harness.knows(udp, 5003, 443, now));
        assertTrue(harness.knows(udp, 5004, 443, now));
        assertEquals(3, harness.consumer().statusSnapshot(now).flows());
    }

    /** A forgotten flow is not reset or purged when its egress goes away: there is nothing left of it. */
    @Test
    void doesNotResetAFlowItHasForgotten() {
        Harness harness = Harness.of(PeerEgressConsumer.DEFAULT_FLOW_CAPACITY, "100.96.0.2");
        int tcp = PeerEgressSegment.IPV4_PROTOCOL_TCP;
        harness.out(tcp, 6000, 443, PeerEgressSegment.FLAG_ACK, EPOCH);
        harness.out(tcp, 6001, 443, PeerEgressSegment.FLAG_ACK, EPOCH + PeerEgressConsumer.TCP_IDLE_MS / 2);

        Map<Long, List<String>> purge =
                harness.consumer().setEgressOnline(EGRESS, false, EPOCH + PeerEgressConsumer.TCP_IDLE_MS);

        assertEquals(1, harness.toTun().size(), "want a reset for the live flow only");
        PeerEgressSegment.Segment reset = PeerEgressSegment.parse(harness.toTun().get(0));
        assertTrue(reset != null && reset.destinationPort() == 6001, "the reset went to the forgotten flow");
        assertEquals(List.of("203.0.113.10/32"), purge.get(EGRESS));
        assertEquals(0, harness.consumer().flowCount());
    }
}
