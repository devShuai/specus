package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Phase two's per-packet decisions, bound to the {@code steering} section of
 * {@code peer-egress-dns-v1.json}.
 *
 * <p>Everything goes through the real consumer: real IPv4 TCP, UDP and ICMP packets through
 * {@link PeerEgressConsumer#handleOutbound}, replies as SPEG1 frames through
 * {@link PeerEgressConsumer#handleInbound}, rule, availability and catalogue changes through the
 * calls the mesh makes. What is checked is what the consumer does, not what it returns: the frames
 * it sends and to which egress (a name-bind control frame ahead of the IP frame when one is due),
 * the reason counted, what it writes back to the TUN, and the destinations it would purge.
 */
class PeerEgressSteeringVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long EPOCH = 1_800_000_000_000L;
    private static final String LOCAL = "100.96.0.2";

    private record Sent(long egress, byte[] frame) {
    }

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertNotNull(value, dotted + " did not parse");
        return value;
    }

    private static List<PeerEgressRule> rules(JsonNode array) throws IOException {
        List<PeerEgressRule> out = new ArrayList<>();
        for (JsonNode node : array) {
            out.add(MAPPER.treeToValue(node, PeerEgressRule.class));
        }
        return out;
    }

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

    /** The IPv4 packet an application would write to the TUN for one of the vector's packets. */
    static byte[] packetFor(JsonNode packet) {
        String protocol = packet.path("protocol").asText();
        int destination = address(packet.path("destination").asText());
        int sourcePort = packet.path("sourcePort").asInt();
        int destinationPort = packet.path("destinationPort").asInt();
        return switch (protocol) {
            case "tcp" -> {
                int flags = flagsOf(packet.path("flags").asText(""));
                boolean syn = (flags & PeerEgressSegment.FLAG_SYN) != 0;
                yield PeerEgressSegment.build(new PeerEgressSegment.Segment(address(LOCAL), destination,
                        sourcePort, destinationPort, syn ? 1000 : 1001,
                        (flags & PeerEgressSegment.FLAG_ACK) != 0 ? 5001 : 0, flags, 65535, syn ? 1360 : 0,
                        new byte[0]));
            }
            case "udp" -> PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(address(LOCAL), destination,
                    sourcePort, destinationPort, "query".getBytes(StandardCharsets.US_ASCII)));
            default -> {
                // An ICMP echo request: header only, which is all the consumer reads.
                byte[] icmp = new byte[28];
                icmp[0] = 0x45;
                icmp[3] = 28;
                icmp[8] = 64;
                icmp[9] = 1;
                writeInt(icmp, 12, address(LOCAL));
                writeInt(icmp, 16, destination);
                icmp[20] = 8;
                yield icmp;
            }
        };
    }

    private static void writeInt(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >>> 24);
        data[offset + 1] = (byte) (value >>> 16);
        data[offset + 2] = (byte) (value >>> 8);
        data[offset + 3] = (byte) value;
    }

    private static int protocolNumber(String name) {
        return switch (name) {
            case "tcp" -> PeerEgressSegment.IPV4_PROTOCOL_TCP;
            case "udp" -> PeerEgressDatagram.IPV4_PROTOCOL_UDP;
            default -> 1;
        };
    }

    /** The outcome the consumer reports for each reason the vector names. */
    private static PeerEgressConsumer.Outcome outcomeFor(String reason) {
        return switch (reason) {
            case "rule" -> PeerEgressConsumer.Outcome.BLOCKED_BY_RULE;
            case "unsupported-protocol" -> PeerEgressConsumer.Outcome.UNSUPPORTED;
            case "fake-ip-unmapped", "fake-ip-stale" -> PeerEgressConsumer.Outcome.BLOCKED_FAKE_IP;
            case "egress-unavailable", "egress-no-domain" -> PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS;
            default -> throw new IllegalArgumentException("unknown reason " + reason);
        };
    }

    private static String flowKey(JsonNode packet) {
        return packet.path("protocol").asText() + ":" + packet.path("sourcePort").asInt() + ":"
                + packet.path("destination").asText() + ":" + packet.path("destinationPort").asInt();
    }

    private static void merge(Map<String, Set<String>> into, Map<Long, List<String>> purge) {
        purge.forEach((egress, destinations) ->
                into.computeIfAbsent(String.valueOf(egress), unused -> new TreeSet<>()).addAll(destinations));
    }

    @Test
    void steersEveryPacketAsTheSharedVectorSays() throws IOException {
        JsonNode cases = PeerEgressFakeIpPoolTests.vector().path("steering");
        assertFalse(cases.isEmpty(), "no steering cases");
        for (JsonNode testCase : cases) {
            replay(testCase);
        }
    }

    private void replay(JsonNode testCase) throws IOException {
        String caseName = testCase.path("name").asText();
        List<Sent> sent = new ArrayList<>();
        List<byte[]> toTun = new ArrayList<>();
        PeerEgressConsumer consumer = new PeerEgressConsumer((egress, frame) -> {
            sent.add(new Sent(egress, frame.clone()));
            return true;
        }, toTun::add);
        PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse(testCase.path("cidr").asText()), () -> EPOCH);
        consumer.configure(rules(testCase.path("rules")), PeerEgressRules.DEFAULT_MESH_CIDR, LOCAL, pool, EPOCH);
        // Which egress each flow went to, so a reply can come from it.
        Map<String, Long> flowEgress = new HashMap<>();

        JsonNode events = testCase.path("events");
        JsonNode results = testCase.path("results");
        assertEquals(events.size(), results.size(), caseName);
        for (int index = 0; index < events.size(); index++) {
            JsonNode event = events.get(index);
            JsonNode expected = results.get(index);
            String where = caseName + " event " + index + " " + event;
            long nowMs = EPOCH + event.path("at").asLong() * 1000;
            sent.clear();
            toTun.clear();

            if (event.has("map")) {
                PeerEgressFakeIpPool.Answer answer = pool.query(event.path("map").asText(), nowMs);
                assertEquals(expected.path("address").asText(), answer.addressText(), where);
            } else if (event.has("packet")) {
                JsonNode packetEvent = event.path("packet");
                byte[] packet = packetFor(packetEvent);
                Map<String, Long> before = new TreeMap<>(consumer.blockedCounts());
                PeerEgressConsumer.Outcome outcome = consumer.handleOutbound(packet, nowMs);
                Map<String, Long> after = new TreeMap<>(consumer.blockedCounts());
                switch (expected.path("outcome").asText()) {
                    case "forwarded" -> {
                        assertEquals(PeerEgressConsumer.Outcome.FORWARDED, outcome, where);
                        assertEquals(before, after, where + ": a forwarded packet was counted as blocked");
                        assertTrue(toTun.isEmpty(), where + ": a forwarded packet was answered locally");
                        long egress = expected.path("egressClientId").asLong();
                        JsonNode bind = expected.path("nameBind");
                        assertEquals(bind.isNull() ? 1 : 2, sent.size(), where + ": frames sent");
                        for (Sent frame : sent) {
                            assertEquals(egress, frame.egress(), where + ": sent to the wrong egress");
                        }
                        if (!bind.isNull()) {
                            PeerEgressFrame.Decoded control = PeerEgressFrame.parse(sent.get(0).frame());
                            assertTrue(control.accepted(), where);
                            assertEquals(PeerEgressFrame.TYPE_CONTROL, control.type(), where + ": the name-bind is not first");
                            assertArrayEquals(PeerEgressFrame.encodeControl(PeerEgressFrame.Control.nameBind(
                                    bind.path("address").asText(), bind.path("name").asText())), control.body(), where);
                        }
                        PeerEgressFrame.Decoded ip = PeerEgressFrame.parse(sent.get(sent.size() - 1).frame());
                        assertTrue(ip.accepted(), where);
                        assertEquals(PeerEgressFrame.TYPE_IP_PACKET, ip.type(), where);
                        assertArrayEquals(packet, ip.body(), where + ": the packet was not sent as written");
                        flowEgress.put(flowKey(packetEvent), egress);
                    }
                    case "blocked" -> {
                        String reason = expected.path("reason").asText();
                        assertEquals(outcomeFor(reason), outcome, where);
                        assertTrue(sent.isEmpty(), where + ": a blocked packet was sent");
                        Map<String, Long> want = new TreeMap<>(before);
                        want.merge(reason, 1L, Long::sum);
                        assertEquals(want, after, where + ": counted");
                        if (expected.path("answered").asBoolean()) {
                            byte[] answer = PeerEgressConsumer.failurePacket(packet, protocolNumber(packetEvent.path("protocol").asText()));
                            assertNotNull(answer, where + ": the vector expects an answer this packet cannot have");
                            assertEquals(1, toTun.size(), where + ": not answered");
                            assertArrayEquals(answer, toTun.get(0), where + ": answered unlike egress-unavailable");
                        } else {
                            assertTrue(toTun.isEmpty(), where + ": answered, but should be dropped silently");
                        }
                    }
                    case "not-mine" -> {
                        assertEquals(PeerEgressConsumer.Outcome.NOT_MINE, outcome, where);
                        assertTrue(sent.isEmpty() && toTun.isEmpty(), where);
                        assertEquals(before, after, where);
                    }
                    default -> throw new IllegalStateException(where + ": unknown outcome " + expected);
                }
            } else if (event.has("reply")) {
                JsonNode reply = event.path("reply");
                Long egress = flowEgress.get(flowKey(reply));
                assertNotNull(egress, where + ": a reply for a flow that never went out");
                byte[] packet = "udp".equals(reply.path("protocol").asText())
                        ? PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(
                                address(reply.path("destination").asText()), address(LOCAL),
                                reply.path("destinationPort").asInt(), reply.path("sourcePort").asInt(),
                                "answer".getBytes(StandardCharsets.US_ASCII)))
                        : PeerEgressSegment.build(new PeerEgressSegment.Segment(
                                address(reply.path("destination").asText()), address(LOCAL),
                                reply.path("destinationPort").asInt(), reply.path("sourcePort").asInt(),
                                5000, 1001, PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]));
                assertTrue(consumer.handleInbound(PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false, packet),
                        egress, nowMs), where);
                boolean delivered = toTun.size() == 1 && java.util.Arrays.equals(packet, toTun.get(0));
                assertEquals(expected.path("accepted").asBoolean(), delivered, where);
            } else {
                // The reference applies the changes and then purges once; the consumer purges as
                // each change arrives, and together they close the same flows.
                Map<String, Set<String>> purge = new TreeMap<>();
                if (event.has("rules")) {
                    merge(purge, consumer.configure(rules(event.path("rules")), PeerEgressRules.DEFAULT_MESH_CIDR,
                            LOCAL, pool, nowMs));
                }
                if (event.has("online")) {
                    for (var entry : iterable(event.path("online"))) {
                        merge(purge, consumer.setEgressOnline(Long.parseLong(entry.getKey()),
                                entry.getValue().asBoolean(), nowMs));
                    }
                }
                if (event.has("catalog")) {
                    Set<Long> capable = new TreeSet<>();
                    for (var entry : iterable(event.path("catalog"))) {
                        if (entry.getValue().asBoolean()) {
                            capable.add(Long.parseLong(entry.getKey()));
                        }
                    }
                    merge(purge, consumer.setDomainCapable(capable, nowMs));
                }
                Map<String, Set<String>> want = new TreeMap<>();
                for (var entry : iterable(expected.path("purge"))) {
                    Set<String> destinations = new TreeSet<>();
                    entry.getValue().forEach(destination -> destinations.add(destination.asText()));
                    want.put(entry.getKey(), destinations);
                }
                assertEquals(want, purge, where);
            }
        }
    }

    private static Iterable<Map.Entry<String, JsonNode>> iterable(JsonNode object) {
        return object::fields;
    }
}
