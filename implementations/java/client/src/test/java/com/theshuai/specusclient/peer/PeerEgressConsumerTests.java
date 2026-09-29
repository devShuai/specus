package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The consumer data plane, tested from the leak side.
 *
 * <p>Almost every case here asks the same question in a different way: can a destination the user
 * routed through an egress end up going out locally instead? A connection that fails is a bad
 * afternoon; a connection that silently uses the wrong source address is the thing the user
 * installed this to prevent.
 */
class PeerEgressConsumerTests {

    private static final long EPOCH = 1_800_000_000_000L;
    private static final String VIRTUAL_IP = "100.96.0.1";

    private final List<long[]> sentTo = new ArrayList<>();
    private final List<byte[]> sentFrames = new ArrayList<>();
    private final List<byte[]> toTun = new ArrayList<>();
    private boolean sendFails;

    private PeerEgressConsumer newConsumer(List<PeerEgressRule> rules, Map<Long, Boolean> online) {
        PeerEgressConsumer consumer = new PeerEgressConsumer(
                (egress, frame) -> {
                    if (sendFails) {
                        return false;
                    }
                    sentTo.add(new long[] {egress});
                    sentFrames.add(frame.clone());
                    return true;
                },
                packet -> toTun.add(packet.clone()));
        consumer.configure(rules, PeerEgressRules.DEFAULT_MESH_CIDR, VIRTUAL_IP, EPOCH);
        online.forEach((egress, up) -> consumer.setEgressOnline(egress, up, EPOCH));
        return consumer;
    }

    private static PeerEgressRule rule(String match, String action, Long target) {
        PeerEgressRule created = new PeerEgressRule();
        created.setMatch(match);
        created.setAction(action);
        created.setEgressClientId(target);
        return created;
    }

    private static List<PeerEgressRule> consumerRules() {
        return new ArrayList<>(List.of(
                rule("203.0.113.0/24", PeerEgressRule.ACTION_EGRESS, 2L),
                rule("192.0.2.0/24", PeerEgressRule.ACTION_BLOCK, null),
                rule("198.51.100.0/24", PeerEgressRule.ACTION_DIRECT, null)));
    }

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertTrue(value != null, dotted + " did not parse");
        return value;
    }

    private static byte[] packetTo(String destination, int port) {
        return PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address(VIRTUAL_IP), address(destination), 40000, port,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 0, new byte[0]));
    }

    private static byte[] replyFrame(String source, String destination, int sourcePort, int destinationPort) {
        byte[] packet = PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address(source), address(destination), sourcePort, destinationPort,
                1, 1001, PeerEgressSegment.FLAG_SYN | PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]));
        return PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false, packet);
    }

    @Test
    void forwardsAMatchedDestination() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));

        assertEquals(PeerEgressConsumer.Outcome.FORWARDED,
                consumer.handleOutbound(packetTo("203.0.113.10", 443), EPOCH));
        assertEquals(1, sentFrames.size());
        assertEquals(2L, sentTo.get(0)[0]);

        PeerEgressFrame.Decoded decoded = PeerEgressFrame.parse(sentFrames.get(0));
        assertTrue(decoded.accepted(), "the frame we built does not parse: " + decoded.code());
        // hop stays clear: this node is a consumer, not an egress forwarding for another one.
        assertFalse(decoded.hop(), "the hop flag was set, which an egress refuses");
        assertEquals("203.0.113.10", decoded.inner().destinationIp());
    }

    /**
     * Traffic no rule claims is not this layer's business. Claiming it would swallow the mesh's own
     * packets, which share the device.
     */
    @Test
    void leavesUnclaimedTrafficAlone() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));

        for (String destination : List.of("8.8.8.8", "198.51.100.10", "100.96.0.5")) {
            assertEquals(PeerEgressConsumer.Outcome.NOT_MINE,
                    consumer.handleOutbound(packetTo(destination, 443), EPOCH), destination);
        }
        assertTrue(sentFrames.isEmpty(), "frames were sent for traffic no rule claims");
    }

    /**
     * The whole point. An egress that cannot take the flow means the packet is dropped, never
     * handed back to the local stack.
     */
    @Test
    void blocksWhenTheEgressIsUnavailable() {
        PeerEgressConsumer neverOnline = newConsumer(consumerRules(), Map.of());
        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS,
                neverOnline.handleOutbound(packetTo("203.0.113.10", 443), EPOCH), "never online");

        PeerEgressConsumer wentOffline = newConsumer(consumerRules(), Map.of());
        wentOffline.setEgressOnline(2, true, EPOCH);
        wentOffline.setEgressOnline(2, false, EPOCH);
        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS,
                wentOffline.handleOutbound(packetTo("203.0.113.10", 443), EPOCH), "went offline");

        PeerEgressConsumer sendBroken = newConsumer(consumerRules(), Map.of(2L, true));
        sendFails = true;
        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS,
                sendBroken.handleOutbound(packetTo("203.0.113.10", 443), EPOCH), "the send fails");
        sendFails = false;
    }

    /**
     * A connection the egress cannot take fails now rather than after the application's own
     * timeout: the SYN is answered with the reset a SYN-SENT socket accepts. A send that failed is
     * not answered, because the session may be re-establishing and the flow may yet recover.
     */
    @Test
    void answersWhatItCannotForward() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of());
        byte[] syn = packetTo("203.0.113.10", 443);

        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NO_EGRESS, consumer.handleOutbound(syn, EPOCH));
        assertEquals(1, toTun.size(), "want the reset written to the TUN");
        PeerEgressSegment.Segment reset = PeerEgressSegment.parse(toTun.get(0));
        assertNotNull(reset, "the answer does not parse as TCP");
        assertEquals(PeerEgressSegment.FLAG_RST | PeerEgressSegment.FLAG_ACK, reset.flags());
        assertEquals(1001, reset.ack());
        assertEquals(address("203.0.113.10"), reset.sourceIp());
        assertEquals(443, reset.sourcePort());
        assertEquals(40000, reset.destinationPort());

        consumer.setEgressOnline(2L, true, EPOCH);
        sendFails = true;
        consumer.handleOutbound(syn, EPOCH);
        assertEquals(1, toTun.size(), "a failed send was answered");
    }

    /**
     * Flows the consumer closes itself are reset from what it remembered: the application's last
     * acknowledgement is where its stack accepts a reset. A flow on which the application has only
     * sent its SYN has nothing to be reset at, and its retransmitted SYN is answered when it comes.
     */
    @Test
    void resetsTheFlowsItPurges() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));
        consumer.handleOutbound(packetTo("203.0.113.10", 443), EPOCH);
        consumer.handleOutbound(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address(VIRTUAL_IP), address("203.0.113.10"), 40000, 443,
                1001, 700001, PeerEgressSegment.FLAG_ACK, 65535, 0,
                "GET / ".getBytes(StandardCharsets.US_ASCII))), EPOCH);
        // A second flow on which only the SYN went.
        consumer.handleOutbound(packetTo("203.0.113.11", 443), EPOCH);
        assertTrue(toTun.isEmpty(), "packets reached the TUN before anything was purged");

        consumer.setEgressOnline(2L, false, EPOCH);

        assertEquals(1, toTun.size(), "want one reset, for the established flow");
        PeerEgressSegment.Segment reset = PeerEgressSegment.parse(toTun.get(0));
        assertNotNull(reset, "the reset does not parse as TCP");
        assertEquals(PeerEgressSegment.FLAG_RST | PeerEgressSegment.FLAG_ACK, reset.flags());
        assertEquals(700001, reset.seq());
        assertEquals(1007, reset.ack());
        assertEquals(address("203.0.113.10"), reset.sourceIp());
        assertEquals(address(VIRTUAL_IP), reset.destinationIp());
        assertEquals(443, reset.sourcePort());
        assertEquals(40000, reset.destinationPort());
    }

    /** A rule change resets the flows it invalidates the same way; a block rule then drops. */
    @Test
    void resetsFlowsARuleChangeInvalidates() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));
        consumer.handleOutbound(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address(VIRTUAL_IP), address("203.0.113.10"), 40000, 443,
                1001, 1, PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0])), EPOCH);

        consumer.configure(List.of(rule("203.0.113.0/24", PeerEgressRule.ACTION_BLOCK, null)),
                PeerEgressRules.DEFAULT_MESH_CIDR, VIRTUAL_IP, EPOCH);

        assertEquals(1, toTun.size(), "want the reset written to the TUN");
        PeerEgressSegment.Segment reset = PeerEgressSegment.parse(toTun.get(0));
        assertNotNull(reset);
        assertEquals(1, reset.seq());
        assertEquals(1001, reset.ack());
        consumer.handleOutbound(packetTo("203.0.113.10", 443), EPOCH);
        assertEquals(1, toTun.size(), "a block rule answered a packet");
    }

    @Test
    void blocksWhatABlockRuleClaims() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));

        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_BY_RULE,
                consumer.handleOutbound(packetTo("192.0.2.10", 443), EPOCH));
        assertTrue(sentFrames.isEmpty(), "a blocked destination was forwarded to an egress");
    }

    /**
     * ICMP has no egress in this version. The rule still says this destination must not go out
     * locally, so it is dropped rather than handed back.
     */
    @Test
    void dropsProtocolsItCannotCarry() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));

        byte[] packet = new byte[28];
        packet[0] = 0x45;
        packet[3] = 28;
        packet[9] = 1; // ICMP
        System.arraycopy(new byte[] {100, 96, 0, 1}, 0, packet, 12, 4);
        System.arraycopy(new byte[] {(byte) 203, 0, 113, 10}, 0, packet, 16, 4);

        assertEquals(PeerEgressConsumer.Outcome.UNSUPPORTED, consumer.handleOutbound(packet, EPOCH));
        assertTrue(sentFrames.isEmpty(), "an unsupported protocol was forwarded");
    }

    /** Four ways the return path could be abused, each closed by its own check. */
    @Test
    void refusesReturnTrafficItDidNotAskFor() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));
        consumer.handleOutbound(packetTo("203.0.113.10", 443), EPOCH);

        // Addressed to somebody else's virtual IP.
        consumer.handleInbound(replyFrame("203.0.113.10", "100.96.0.9", 443, 40000), 2, EPOCH);
        // Claiming a mesh address, which would let an egress speak as another peer.
        consumer.handleInbound(replyFrame("100.96.0.5", VIRTUAL_IP, 443, 40000), 2, EPOCH);
        // From an address no flow of ours is talking to.
        consumer.handleInbound(replyFrame("198.51.100.10", VIRTUAL_IP, 443, 40000), 2, EPOCH);
        // From the right address but the wrong egress.
        consumer.handleInbound(replyFrame("203.0.113.10", VIRTUAL_IP, 443, 40000), 3, EPOCH);

        assertTrue(toTun.isEmpty(), toTun.size() + " forged replies reached the local stack");

        // The genuine reply does get through, so the checks above are not simply refusing everything.
        consumer.handleInbound(replyFrame("203.0.113.10", VIRTUAL_IP, 443, 40000), 2, EPOCH);
        assertEquals(1, toTun.size(), "the genuine reply did not reach the local stack");
    }

    /**
     * An established flow survives a rule change that still sends it to the same egress, and does
     * not survive one that stops.
     */
    @Test
    void purgesFlowsARuleChangeInvalidates() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));
        consumer.handleOutbound(packetTo("203.0.113.10", 443), EPOCH);
        assertEquals(1, consumer.flowCount());

        List<PeerEgressRule> widened = consumerRules();
        widened.add(rule("10.1.0.0/16", PeerEgressRule.ACTION_BLOCK, null));
        Map<Long, List<String>> unchanged =
                consumer.configure(widened, PeerEgressRules.DEFAULT_MESH_CIDR, VIRTUAL_IP, EPOCH);
        assertTrue(unchanged.isEmpty(), "an unrelated rule addition purged something");
        assertEquals(1, consumer.flowCount());

        Map<Long, List<String>> purge = consumer.configure(
                List.of(rule("203.0.113.0/24", PeerEgressRule.ACTION_BLOCK, null)),
                PeerEgressRules.DEFAULT_MESH_CIDR, VIRTUAL_IP, EPOCH);

        assertEquals(0, consumer.flowCount(), "a flow survived the rule change");
        assertEquals(List.of("203.0.113.10/32"), purge.get(2L));
    }

    /**
     * Without the purge the egress holds the socket until its own idle timer, and the user sees a
     * connection that is dead at one end and open at the other.
     */
    @Test
    void purgesFlowsWhenTheEgressGoesOffline() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));
        consumer.handleOutbound(packetTo("203.0.113.10", 443), EPOCH);
        consumer.handleOutbound(packetTo("203.0.113.11", 443), EPOCH);

        Map<Long, List<String>> purge = consumer.setEgressOnline(2, false, EPOCH);
        assertEquals(0, consumer.flowCount(), "flows survived the egress going offline");
        // Sorted, so two runs of the same change produce the same message.
        assertEquals(List.of("203.0.113.10/32", "203.0.113.11/32"), purge.get(2L));
    }

    /**
     * A rejection removes the matching flow rather than leaving it to expire.
     */
    @Test
    void dropsAFlowTheEgressRejected() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));
        consumer.handleOutbound(packetTo("203.0.113.10", 443), EPOCH);

        byte[] body = PeerEgressFrame.encodeControl(PeerEgressFrame.Control.flowReject(
                "tcp", VIRTUAL_IP, 40000, "203.0.113.10", 443, PeerEgressCodes.PORT_DENIED));
        consumer.handleInbound(
                PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false, body), 2, EPOCH);

        assertEquals(0, consumer.flowCount(), "a flow survived a flow-reject");
        assertEquals(1L, consumer.blockedCounts().get("rejected-egress_port_denied"));
    }

    @Test
    void rejectionResetsOnlyTheSendingEgressFlowEvenWithoutRemoteReset() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true, 3L, true));
        consumer.handleOutbound(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address(VIRTUAL_IP), address("203.0.113.10"), 40000, 443,
                1001, 700001, PeerEgressSegment.FLAG_ACK, 65535, 0,
                "hello".getBytes(StandardCharsets.US_ASCII))), EPOCH);
        byte[] frame = PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false,
                PeerEgressFrame.encodeControl(PeerEgressFrame.Control.flowReject(
                        "tcp", VIRTUAL_IP, 40000, "203.0.113.10", 443, PeerEgressCodes.DISABLED)));
        consumer.handleInbound(frame, 3, EPOCH);
        assertEquals(1, consumer.flowCount());
        assertTrue(toTun.isEmpty());
        assertTrue(consumer.blockedCounts().isEmpty());
        consumer.handleInbound(frame, 2, EPOCH);
        assertEquals(0, consumer.flowCount());
        assertEquals(1, toTun.size());
        var reset = PeerEgressSegment.parse(toTun.get(0));
        assertNotNull(reset);
        assertEquals(PeerEgressSegment.FLAG_RST | PeerEgressSegment.FLAG_ACK, reset.flags());
        assertEquals(700001, reset.seq());
        assertEquals(1006, reset.ack());
        consumer.handleInbound(frame, 2, EPOCH);
        consumer.handleInbound(PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false, toTun.get(0)), 2, EPOCH);
        assertEquals(1, toTun.size());
        assertEquals(1L, consumer.blockedCounts().get("rejected-egress_disabled"));
    }

    /**
     * Counted by reason and never by destination. A per-destination record would be the user's own
     * browsing history, which is the same reason the egress report aggregates by code.
     */
    @Test
    void countsBlocksByReasonOnly() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of());
        consumer.handleOutbound(packetTo("192.0.2.10", 443), EPOCH);
        consumer.handleOutbound(packetTo("192.0.2.11", 443), EPOCH);
        consumer.handleOutbound(packetTo("203.0.113.10", 443), EPOCH);

        Map<String, Long> counts = consumer.blockedCounts();
        assertEquals(2L, counts.get("rule"));
        assertEquals(1L, counts.get("egress-unavailable"));
        for (String reason : counts.keySet()) {
            for (String destination : List.of("192.0.2", "203.0.113")) {
                assertFalse(reason.startsWith(destination),
                        "a destination leaked into the counters as " + reason);
            }
        }
    }

    @Test
    void ignoresNonEgressFrames() {
        PeerEgressConsumer consumer = newConsumer(consumerRules(), Map.of(2L, true));
        byte[] bare = PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address("203.0.113.10"), address(VIRTUAL_IP), 443, 40000,
                0, 0, PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]));
        assertFalse(consumer.handleInbound(bare, 2, EPOCH),
                "a bare IPv4 packet was claimed by the egress return path");
    }
}
