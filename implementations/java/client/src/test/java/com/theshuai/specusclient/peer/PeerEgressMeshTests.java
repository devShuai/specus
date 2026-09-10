package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The joins between the egress plane and Peer Mesh.
 *
 * <p>What is worth testing here is not the plane, which has its own suites, but the decisions the
 * wiring makes on its behalf: which role is offered a frame first, what happens to a frame that
 * arrives before anything configured this node, and whether a frame leaves through the queue rather
 * than inline under the plane's lock.
 */
class PeerEgressMeshTests {

    private static final String VIRTUAL_IP = "100.96.0.1";

    @TempDir
    Path directory;

    private final List<long[]> sentTo = new ArrayList<>();
    private final List<byte[]> sentFrames = new ArrayList<>();
    private final List<byte[]> toDevice = new ArrayList<>();
    private PeerEgressMesh mesh;

    private final class FakeHost implements PeerEgressMesh.Host {
        @Override
        public boolean sendToPeer(long peerId, byte[] frame) {
            synchronized (PeerEgressMeshTests.this) {
                sentTo.add(new long[] {peerId});
                sentFrames.add(frame.clone());
            }
            return true;
        }

        @Override
        public void writeToDevice(byte[] packet) {
            synchronized (PeerEgressMeshTests.this) {
                toDevice.add(packet.clone());
            }
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
            return VIRTUAL_IP;
        }

        @Override
        public List<String> deploymentDenyCidrs() {
            return List.of("203.0.113.250/32");
        }

        @Override
        public List<String> peerEndpointAddresses() {
            return List.of("198.51.100.240");
        }

        @Override
        public Integer pathMtuForPeer(long peerId) {
            return null;
        }

        @Override
        public Path routeJournalPath() {
            return directory.resolve("egress-routes.json");
        }
    }

    @AfterEach
    void stop() {
        if (mesh != null) {
            mesh.close();
        }
    }

    private PeerEgressMesh newMesh() {
        mesh = new PeerEgressMesh(new FakeHost());
        return mesh;
    }

    private synchronized List<byte[]> frames() {
        return List.copyOf(sentFrames);
    }

    private synchronized List<byte[]> written() {
        return List.copyOf(toDevice);
    }

    private static void waitFor(String what, BooleanSupplier condition) {
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                fail("interrupted while waiting for " + what);
            }
        }
        fail("timed out waiting for " + what);
    }

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertTrue(value != null, dotted + " did not parse");
        return value;
    }

    private static byte[] synTo(String destination) {
        return PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false,
                PeerEgressSegment.build(new PeerEgressSegment.Segment(
                        address(VIRTUAL_IP), address(destination), 40000, 443,
                        1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0])));
    }

    private static String configFor(long revision, String cidr) {
        return "{\"type\":\"egress-config\",\"enabled\":true,\"revision\":" + revision
                + ",\"scope\":\"PUBLIC\",\"allowedConsumerClientIds\":[7],"
                + "\"destinationRules\":[{\"cidr\":\"" + cidr + "\",\"protocols\":[\"tcp\",\"udp\"],"
                + "\"portRanges\":[[1,65535]]}],"
                + "\"limits\":{\"maxConcurrentFlows\":8,\"maxFlowsPerConsumer\":4,\"idleTimeoutSeconds\":60}}";
    }

    /**
     * A frame that arrives before anything configured this node is dropped, not answered. Building
     * the plane on first contact would let any peer turn an unconfigured device into an egress by
     * sending it one.
     */
    @Test
    void aFrameBeforeAnyConfigIsDroppedRatherThanAnswered() {
        PeerEgressMesh wiring = newMesh();

        assertTrue(wiring.handleInboundFrame(7, synTo("203.0.113.10")),
                "the frame was left for the mesh's own dispatch");
        assertTrue(frames().isEmpty(), "an unconfigured node answered a frame");
    }

    /** A payload that is not SPEG1 is left for the mesh's other cases. */
    @Test
    void aNonEgressPayloadIsNotClaimed() {
        PeerEgressMesh wiring = newMesh();
        byte[] bare = PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address("203.0.113.10"), address(VIRTUAL_IP), 443, 40000,
                0, 0, PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]));

        assertFalse(wiring.handleInboundFrame(7, bare), "a bare IPv4 packet was claimed");
    }

    /**
     * A pushed config builds the plane and takes effect, and the frames it produces leave through
     * the queue rather than inline under the plane's lock.
     */
    @Test
    void aPushedConfigMakesTheNodeAnEgress() {
        PeerEgressMesh wiring = newMesh();
        wiring.applyEgressConfig(configFor(1, "203.0.113.0/24"));

        assertTrue(wiring.handleInboundFrame(7, synTo("203.0.113.10")), "the frame was not claimed");
        waitFor("the SYN-ACK to be sent", () -> !frames().isEmpty());

        PeerEgressFrame.Decoded decoded = PeerEgressFrame.parse(frames().get(0));
        assertTrue(decoded.accepted(), "the frame we produced does not parse");
        assertEquals(PeerEgressFrame.TYPE_IP_PACKET, decoded.type());
    }

    /**
     * A destination the policy does not cover is refused, and the refusal reaches the consumer as a
     * control message rather than as silence.
     */
    @Test
    void aRefusedDestinationIsToldWhy() {
        PeerEgressMesh wiring = newMesh();
        wiring.applyEgressConfig(configFor(1, "203.0.113.0/24"));

        wiring.handleInboundFrame(7, synTo("198.51.100.10"));
        waitFor("a refusal to be sent", () -> frames().stream().anyMatch(raw -> {
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
            return frame.accepted() && frame.type() == PeerEgressFrame.TYPE_CONTROL;
        }));
    }

    /**
     * A snapshot at or below the last accepted one is ignored, so a reordered or replayed push
     * cannot walk the policy backwards.
     */
    @Test
    void aReplayedRevisionIsIgnored() {
        PeerEgressMesh wiring = newMesh();
        wiring.applyEgressConfig(configFor(5, "203.0.113.0/24"));
        // An older snapshot that would have narrowed the policy to something else.
        wiring.applyEgressConfig(configFor(4, "198.51.100.0/24"));

        wiring.handleInboundFrame(7, synTo("203.0.113.10"));
        waitFor("the newer policy to still be in force", () -> frames().stream().anyMatch(raw -> {
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
            return frame.accepted() && frame.type() == PeerEgressFrame.TYPE_IP_PACKET;
        }));
    }

    /** A message that is not an egress-config must not configure anything. */
    @Test
    void anUnreadableConfigChangesNothing() {
        PeerEgressMesh wiring = newMesh();
        wiring.applyEgressConfig("{\"type\":\"egress-catalog\",\"revision\":1}");

        assertTrue(wiring.handleInboundFrame(7, synTo("203.0.113.10")));
        assertTrue(frames().isEmpty(), "a catalogue was read as a policy");
    }

    /**
     * Traffic no consumer rule claims stays with the mesh's own handling. Claiming it would swallow
     * the mesh's packets, which share the device.
     */
    @Test
    void outboundTrafficNoRuleClaimsIsLeftAlone() {
        PeerEgressMesh wiring = newMesh();
        wiring.applyRules(List.of(rule("203.0.113.0/24", PeerEgressRule.ACTION_EGRESS, 2L)));

        byte[] packet = PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address(VIRTUAL_IP), address("8.8.8.8"), 40000, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 0, new byte[0]));
        assertFalse(wiring.handleOutbound(packet), "an unclaimed destination was swallowed");
    }

    /**
     * A destination a rule claims is this layer's, even when the egress cannot take it. Handing it
     * back would send it out locally, which is the leak the whole feature exists to prevent.
     */
    @Test
    void outboundTrafficARuleClaimsIsNotHandedBack() {
        PeerEgressMesh wiring = newMesh();
        wiring.applyRules(List.of(rule("203.0.113.0/24", PeerEgressRule.ACTION_EGRESS, 2L)));

        byte[] packet = PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address(VIRTUAL_IP), address("203.0.113.10"), 40000, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 0, new byte[0]));
        assertTrue(wiring.handleOutbound(packet), "a claimed destination was handed back");
    }

    /**
     * An egress going offline closes its flows and tells it to drop its side, so the user does not
     * see a connection that is dead at one end and open at the other.
     */
    @Test
    void anEgressGoingOfflinePurgesItsFlows() {
        PeerEgressMesh wiring = newMesh();
        wiring.applyRules(List.of(rule("203.0.113.0/24", PeerEgressRule.ACTION_EGRESS, 2L)));
        wiring.syncEgressAvailability(Map.of(2L, true));

        byte[] packet = PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address(VIRTUAL_IP), address("203.0.113.10"), 40000, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 0, new byte[0]));
        assertTrue(wiring.handleOutbound(packet));

        synchronized (this) {
            sentFrames.clear();
        }
        wiring.syncEgressAvailability(Map.of(2L, false));

        assertTrue(frames().stream().anyMatch(raw -> {
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
            if (!frame.accepted() || frame.type() != PeerEgressFrame.TYPE_CONTROL) {
                return false;
            }
            PeerEgressFrame.Control control = PeerEgressFrame.decodeControl(frame.body());
            return control != null
                    && PeerEgressFrame.CONTROL_FLOW_PURGE.equals(control.type())
                    && control.destinations().contains("203.0.113.10/32");
        }), "no flow-purge reached the egress");
    }

    /** Revocation reaches the plane even though the plane never asks the mesh anything. */
    @Test
    void aClosingSessionRevokesThatPeersFlows() {
        PeerEgressMesh wiring = newMesh();
        wiring.applyEgressConfig(configFor(1, "203.0.113.0/24"));
        wiring.handleInboundFrame(7, synTo("203.0.113.10"));
        waitFor("the flow to open", () -> !frames().isEmpty());

        synchronized (this) {
            sentFrames.clear();
        }
        wiring.revokeConsumer(7);

        waitFor("the revoked consumer to be told", () -> frames().stream().anyMatch(raw -> {
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
            return frame.accepted() && frame.type() == PeerEgressFrame.TYPE_CONTROL;
        }));
    }

    /** Closing has to stop forwarding, not merely ask it to stop. */
    @Test
    void closingStopsForwarding() {
        PeerEgressMesh wiring = newMesh();
        wiring.applyEgressConfig(configFor(1, "203.0.113.0/24"));
        wiring.handleInboundFrame(7, synTo("203.0.113.10"));
        waitFor("the flow to open", () -> !frames().isEmpty());

        wiring.close();
        synchronized (this) {
            sentFrames.clear();
        }

        wiring.handleInboundFrame(7, synTo("203.0.113.11"));
        // A shut-down plane refuses rather than opening, so whatever it says must not be a SYN-ACK.
        assertTrue(frames().stream().noneMatch(raw -> {
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
            if (!frame.accepted() || frame.type() != PeerEgressFrame.TYPE_IP_PACKET) {
                return false;
            }
            PeerEgressSegment.Segment segment = PeerEgressSegment.parse(frame.body());
            return segment != null && segment.has(PeerEgressSegment.FLAG_SYN)
                    && segment.has(PeerEgressSegment.FLAG_ACK);
        }), "a shut-down node completed a handshake");
    }

    private static PeerEgressRule rule(String match, String action, Long target) {
        PeerEgressRule created = new PeerEgressRule();
        created.setMatch(match);
        created.setAction(action);
        created.setEgressClientId(target);
        return created;
    }
}
