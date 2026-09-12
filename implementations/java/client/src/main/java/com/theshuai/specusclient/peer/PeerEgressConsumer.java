package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import lombok.extern.slf4j.Slf4j;

/**
 * The consumer data plane: packets leaving the TUN, and the replies coming back.
 *
 * <p>The rule that shapes this class is that a destination matched by an egress rule must never
 * quietly go out locally. If the egress is offline, its authorization has been withdrawn, or the
 * flow cannot be opened, the packet is dropped. Falling back to the local stack would send the
 * user's traffic from the address they arranged for it not to come from, which is worse than the
 * connection failing, because it fails silently and in the direction they were guarding against.
 *
 * <p>Time arrives as an argument. Not safe for concurrent use on its own; the caller serialises
 * access the same way the Go consumer's mutex does.
 */
@Slf4j
final class PeerEgressConsumer {

    /** What happened to one packet. */
    enum Outcome {
        /**
         * No rule claims this destination, so the caller carries on with its own handling. This is
         * not a decision about the packet, it is the absence of one.
         */
        NOT_MINE,
        FORWARDED,
        /** A rule that says block. */
        BLOCKED_BY_RULE,
        /** A rule that says egress, for an egress that cannot take it. */
        BLOCKED_NO_EGRESS,
        /** A packet this version cannot carry, such as IPv6 or ICMP. */
        UNSUPPORTED;

        @Override
        public String toString() {
            return switch (this) {
                case FORWARDED -> "forwarded";
                case BLOCKED_BY_RULE -> "blocked-by-rule";
                case BLOCKED_NO_EGRESS -> "blocked-no-egress";
                case UNSUPPORTED -> "unsupported";
                default -> "not-mine";
            };
        }
    }

    /** Delivers one SPEG1 frame to an egress peer. Returning false means it did not go. */
    interface Sender {
        boolean send(long egress, byte[] frame);
    }

    /** Writes one packet to the local stack. */
    interface TunWriter {
        void write(byte[] packet);
    }

    private static final int IPV4_MIN_HEADER_BYTES = 20;

    /**
     * One flow this node opened through an egress, tracked so a reply can be matched to something
     * we actually asked for, and so a rule change can close exactly the flows it invalidates.
     */
    private static final class Flow {
        final long egress;
        long lastSeenMs;

        Flow(long egress, long lastSeenMs) {
            this.egress = egress;
            this.lastSeenMs = lastSeenMs;
        }
    }

    private final Sender sender;
    private final TunWriter tunWriter;

    private List<PeerEgressRule> rules = List.of();
    private String meshCidr = PeerEgressRules.DEFAULT_MESH_CIDR;
    /** This node's mesh address, which every reply must be addressed to. */
    private String virtualIp = "";

    /** Which egress peers can currently take a flow. Absent means no. */
    private final Map<Long, Boolean> online = new LinkedHashMap<>();

    private final Map<PeerEgressFlowTable.Key, Flow> flows = new LinkedHashMap<>();
    private final Map<String, Long> blocked = new TreeMap<>();

    PeerEgressConsumer(Sender sender, TunWriter tunWriter) {
        this.sender = sender;
        this.tunWriter = tunWriter;
    }

    /**
     * What an operator can read, for the status surface.
     *
     * <p>No lock here, for the same reason nothing else in this class has one: the caller
     * serialises access. Copies of the collections, because the caller is a diagnostic reader and
     * this consumer goes on mutating its own.
     */
    PeerEgressStatus.ConsumerSnapshot statusSnapshot() {
        return new PeerEgressStatus.ConsumerSnapshot(List.copyOf(rules), meshCidr,
                new java.util.LinkedHashMap<>(online), flows.size(),
                new java.util.TreeMap<>(blocked));
    }

    /**
     * Installs a rule set and closes the flows it invalidates.
     *
     * <p>Established flows survive a rule change unless their rule stopped saying egress or stopped
     * matching. The returned purge messages tell each affected egress to close its side; without
     * them the egress would hold the socket until its own idle timer, and the user would see a
     * connection that is dead at one end and open at the other.
     */
    Map<Long, List<String>> configure(
            List<PeerEgressRule> newRules, String newMeshCidr, String newVirtualIp, long nowMs) {
        rules = newRules == null ? List.of() : List.copyOf(newRules);
        if (newMeshCidr != null && !newMeshCidr.trim().isEmpty()) {
            meshCidr = newMeshCidr.trim();
        }
        virtualIp = newVirtualIp == null ? "" : newVirtualIp.trim();
        return purgeInvalidated(nowMs);
    }

    /**
     * Records whether an egress peer can take flows.
     *
     * <p>Going offline closes its flows rather than leaving them to time out, because every packet
     * they would carry in the meantime is one the rule says must not go out locally.
     */
    Map<Long, List<String>> setEgressOnline(long egress, boolean isOnline, long nowMs) {
        online.put(egress, isOnline);
        return isOnline ? Map.of() : purgeInvalidated(nowMs);
    }

    /**
     * Drops flows whose rule no longer sends them to the egress they are using, and returns the
     * destinations to purge per egress.
     *
     * <p>The destinations are sorted. The flows they came from live in a map, so without it the
     * same rule change would produce them in a different order every run, and an operator comparing
     * two flow-purge messages could not tell a real difference from iteration order.
     */
    private Map<Long, List<String>> purgeInvalidated(long nowMs) {
        Map<Long, TreeSet<String>> purge = new TreeMap<>();
        List<PeerEgressFlowTable.Key> dropped = new ArrayList<>();
        for (Map.Entry<PeerEgressFlowTable.Key, Flow> entry : flows.entrySet()) {
            PeerEgressFlowTable.Key key = entry.getKey();
            Flow flow = entry.getValue();
            PeerEgressRules.Match match =
                    PeerEgressRules.match(rules, Ipv4Cidr.format(key.remoteIp()), meshCidr);
            boolean stillOurs = PeerEgressRule.ACTION_EGRESS.equals(match.action())
                    && match.egressClientId() != null
                    && match.egressClientId() == flow.egress
                    && Boolean.TRUE.equals(online.get(flow.egress));
            if (stillOurs) {
                continue;
            }
            dropped.add(key);
            purge.computeIfAbsent(flow.egress, unused -> new TreeSet<>())
                    .add(Ipv4Cidr.format(key.remoteIp()) + "/32");
        }
        for (PeerEgressFlowTable.Key key : dropped) {
            flows.remove(key);
        }

        Map<Long, List<String>> out = new LinkedHashMap<>();
        for (Map.Entry<Long, TreeSet<String>> entry : purge.entrySet()) {
            out.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        return out;
    }

    /**
     * Decides what happens to one packet read from the TUN.
     *
     * <p>A destination no rule claims returns {@link Outcome#NOT_MINE}, so the caller falls through
     * to its own handling. That is what keeps this from claiming the mesh's own traffic, which
     * shares the device.
     */
    Outcome handleOutbound(byte[] packet, long nowMs) {
        if (packet == null || packet.length < IPV4_MIN_HEADER_BYTES) {
            return Outcome.NOT_MINE;
        }
        if (((packet[0] & 0xff) >>> 4) != 4) {
            // IPv6 has no rules in this version, so nothing can claim it and it is not ours.
            return Outcome.NOT_MINE;
        }
        String destination = PeerIpPacket.destinationIpv4(packet);
        if (destination == null || destination.isEmpty()) {
            return Outcome.NOT_MINE;
        }

        PeerEgressRules.Match match = PeerEgressRules.match(rules, destination, meshCidr);
        if (!match.matched()
                || (!PeerEgressRule.ACTION_EGRESS.equals(match.action())
                        && !PeerEgressRule.ACTION_BLOCK.equals(match.action()))) {
            return Outcome.NOT_MINE;
        }
        if (PeerEgressRule.ACTION_BLOCK.equals(match.action())) {
            recordBlocked("rule");
            return Outcome.BLOCKED_BY_RULE;
        }

        int protocol = PeerIpPacket.protocol(packet);
        if (protocol != PeerEgressSegment.IPV4_PROTOCOL_TCP
                && protocol != PeerEgressDatagram.IPV4_PROTOCOL_UDP) {
            // ICMP and anything else this version does not carry. The rule says this destination
            // must not go out locally, so it is dropped rather than handed back.
            recordBlocked("unsupported-protocol");
            return Outcome.UNSUPPORTED;
        }
        Long egress = match.egressClientId();
        if (egress == null || !Boolean.TRUE.equals(online.get(egress))) {
            recordBlocked("egress-unavailable");
            return Outcome.BLOCKED_NO_EGRESS;
        }

        PeerEgressFlowTable.Key key = flowKeyFor(packet, protocol);
        if (key != null) {
            Flow flow = flows.get(key);
            if (flow != null) {
                flow.lastSeenMs = nowMs;
            } else {
                flows.put(key, new Flow(egress, nowMs));
            }
        }

        if (sender == null) {
            return Outcome.BLOCKED_NO_EGRESS;
        }
        // hop stays clear: this node is acting as a consumer, not forwarding on behalf of another
        // egress. An egress that receives it set refuses, which is what stops multi-hop chains.
        byte[] frame = PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false, packet);
        if (!sender.send(egress, frame)) {
            recordBlocked("send-failed");
            return Outcome.BLOCKED_NO_EGRESS;
        }
        return Outcome.FORWARDED;
    }

    /**
     * Builds the four-tuple as the consumer sees it, which is the mirror of what the egress
     * recorded, so a reply can be matched against it.
     */
    private static PeerEgressFlowTable.Key flowKeyFor(byte[] packet, int protocol) {
        int ihl = (packet[0] & 0x0f) * 4;
        if (ihl < IPV4_MIN_HEADER_BYTES || packet.length < ihl + 4) {
            return null;
        }
        return new PeerEgressFlowTable.Key(
                protocol,
                readInt(packet, 12),
                readShort(packet, ihl),
                readInt(packet, 16),
                readShort(packet, ihl + 2));
    }

    private static int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24) | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8) | (data[offset + 3] & 0xff);
    }

    private static int readShort(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    /**
     * Takes one SPEG1 frame addressed to this node as a consumer and writes the packet to the TUN.
     * Reports whether the frame was this node's to handle.
     *
     * <p>A node can be a consumer and an egress at once, and both roles receive type=1 frames, so
     * the two have to be told apart before either acts. A reply is addressed to this node's own
     * virtual IP; a frame for the egress role is addressed to the wider network. Control messages
     * split by type: flow-reject travels egress to consumer, flow-purge the other way. Anything not
     * ours is left for the egress runtime rather than counted as an abuse of the return path.
     */
    boolean handleInbound(byte[] frame, long fromEgress, long nowMs) {
        if (!PeerEgressFrame.looksLikeFrame(frame)) {
            return false;
        }
        PeerEgressFrame.Decoded parsed = PeerEgressFrame.parse(frame);
        if (!parsed.accepted()) {
            // A frame nobody can read is not claimed. The egress runtime refuses it with its own
            // code, which is the one an operator needs, and counting it here as well would report
            // one malformed frame twice.
            return false;
        }
        if (parsed.type() == PeerEgressFrame.TYPE_CONTROL) {
            PeerEgressFrame.Control control = PeerEgressFrame.decodeControl(parsed.body());
            if (control == null || !PeerEgressFrame.CONTROL_FLOW_REJECT.equals(control.type())) {
                return false;
            }
            handleFlowReject(control, fromEgress);
            return true;
        }
        if (parsed.type() != PeerEgressFrame.TYPE_IP_PACKET) {
            return false;
        }

        if (virtualIp.isEmpty() || !virtualIp.equals(parsed.inner().destinationIp())) {
            // Not addressed to us as a consumer, so it belongs to the egress role if this node has
            // one. Refusing it here would break a node that is both.
            return false;
        }
        Integer source = Ipv4Cidr.parseAddress(parsed.inner().sourceIp());
        Ipv4Cidr mesh = Ipv4Cidr.parse(meshCidr);
        if (source == null || (mesh != null && mesh.contains(source))) {
            // A reply claiming a mesh address would let an egress speak as another peer.
            recordBlocked("return-mesh-source");
            return true;
        }
        if (!hasReturnFlow(parsed.inner(), fromEgress, nowMs)) {
            recordBlocked("return-no-flow");
            return true;
        }
        if (tunWriter != null) {
            tunWriter.write(parsed.body());
        }
        return true;
    }

    /**
     * Reports whether a reply belongs to a flow this node opened through this egress. The tuple is
     * mirrored, since the reply travels the other way.
     */
    private boolean hasReturnFlow(PeerEgressFrame.Inner inner, long fromEgress, long nowMs) {
        Integer remote = Ipv4Cidr.parseAddress(inner.sourceIp());
        Integer local = Ipv4Cidr.parseAddress(inner.destinationIp());
        if (remote == null || local == null) {
            return false;
        }
        Flow flow = flows.get(new PeerEgressFlowTable.Key(
                inner.protocol(), local, inner.destinationPort(), remote, inner.sourcePort()));
        if (flow == null || flow.egress != fromEgress) {
            return false;
        }
        flow.lastSeenMs = nowMs;
        return true;
    }

    /**
     * Reads a flow-reject. It is diagnostic: the application learns the flow is dead from the reset
     * the egress user-space stack sends, and this only supplies a readable reason.
     */
    private void handleFlowReject(PeerEgressFrame.Control control, long fromEgress) {
        recordBlocked("rejected-" + control.code().toLowerCase(Locale.ROOT));
        Integer remote = Ipv4Cidr.parseAddress(control.destinationIp());
        Integer local = Ipv4Cidr.parseAddress(control.sourceIp());
        if (remote != null && local != null) {
            flows.remove(new PeerEgressFlowTable.Key(
                    protocolNumberFor(control.protocol()),
                    local, control.sourcePort(), remote, control.destinationPort()));
        }
        log.info("[peer-egress-consumer] egress={} refused {}:{} code={}",
                fromEgress, control.destinationIp(), control.destinationPort(), control.code());
    }

    private static int protocolNumberFor(String name) {
        String trimmed = name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
        return switch (trimmed) {
            case "udp" -> PeerEgressDatagram.IPV4_PROTOCOL_UDP;
            case "tcp" -> PeerEgressSegment.IPV4_PROTOCOL_TCP;
            default -> 0;
        };
    }

    /**
     * Counts why traffic did not go out. Aggregated by reason and never by destination, for the
     * same reason the egress report is: a per-destination record is a browsing history, and this
     * one would be the user's own.
     */
    private void recordBlocked(String reason) {
        blocked.merge(reason, 1L, Long::sum);
    }

    Map<String, Long> blockedCounts() {
        return Map.copyOf(blocked);
    }

    int flowCount() {
        return flows.size();
    }
}
