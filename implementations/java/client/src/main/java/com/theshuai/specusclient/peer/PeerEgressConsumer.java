package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressDns;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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
 * <p>While phase two runs (protocol/spec/peer-egress-dns.md) a destination inside the fake-IP pool
 * is decided by the name it stands for, by domain rules only, and goes to its egress preceded by a
 * name-bind; everything outside the pool is decided as in phase one. Shared cases: the
 * {@code steering} section of {@code peer-egress-dns-v1.json}.
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
        UNSUPPORTED,
        /**
         * Phase two: a packet to a fake address that stands for no name, or for a name no rule
         * sends anywhere any more.
         */
        BLOCKED_FAKE_IP,
        /** A DNS query to the responder, which took it. */
        DNS,
        /** A DNS query to the responder from an address that is not this machine's: dropped. */
        BLOCKED_NOT_LOCAL;

        @Override
        public String toString() {
            return switch (this) {
                case FORWARDED -> "forwarded";
                case BLOCKED_BY_RULE -> "blocked-by-rule";
                case BLOCKED_NO_EGRESS -> "blocked-no-egress";
                case UNSUPPORTED -> "unsupported";
                case BLOCKED_FAKE_IP -> "blocked-fake-ip";
                case DNS -> "dns";
                case BLOCKED_NOT_LOCAL -> "blocked-not-local";
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

    /*
     * When a flow is forgotten. Without these an entry left only on a revocation or a flow-reject,
     * so every flow ever made stayed in memory and the status's flow count only ever grew. The
     * same for all three clients: protocol/spec/peer-egress.md (resource limits) and
     * protocol/test-vectors/peer-egress-consumer-flows-v1.json.
     */

    /** A datagram flow is forgotten this long after its last packet in either direction. */
    static final long UDP_IDLE_MS = 180_000L;
    /**
     * A TCP flow that has not closed is forgotten this long after its last packet. Long, because
     * forgetting a live connection refuses its replies; the egress's own idle timer has normally
     * ended the flow well before this.
     */
    static final long TCP_IDLE_MS = 7_200_000L;
    /**
     * A TCP flow is forgotten this long after a reset in either direction, or after a FIN has been
     * seen both ways. Kept that long so the last ACK and any retransmitted FIN still get through.
     */
    static final long TCP_CLOSED_LINGER_MS = 120_000L;
    /** The most flows remembered at once. */
    static final int DEFAULT_FLOW_CAPACITY = 65_536;
    /**
     * The least time between two walks of the whole table. Lookups already treat a lapsed entry as
     * gone, so the walk only releases memory, and a table whose entries lapse one after another
     * must not be walked once per packet.
     */
    static final long SWEEP_INTERVAL_MS = 1_000L;

    /**
     * One flow this node opened through an egress, tracked so a reply can be matched to something
     * we actually asked for, and so a rule change can close exactly the flows it invalidates.
     */
    private static final class Flow {
        final int protocol;
        final long egress;
        /** When it was registered, as a counter: the tie-break when two flows are equally stale. */
        final long registration;
        long lastSeenMs;
        /** A FIN seen from the application, and one seen from the egress. */
        boolean finOut;
        boolean finIn;
        /**
         * Set by a reset in either direction or a FIN both ways, and never cleared: packets after
         * that do not keep the flow alive, and a new SYN on the four-tuple starts a new flow.
         */
        boolean closed;
        long closedAtMs;
        /**
         * What the application last said on a TCP flow, kept so the flow can be reset without
         * waiting for it to speak again. Its acknowledgement number is its receive-next, the one
         * sequence number a stack accepts a reset at (RFC 5961); its next sequence number is what
         * the reset acknowledges. Unknown until the application has sent a segment carrying ACK.
         */
        boolean appAckKnown;
        int appAck;
        int appSeqNext;
        /**
         * Whether the egress has answered this flow at all. Until it has, every datagram of a UDP
         * flow to a fake address carries a name-bind: UDP has no retransmitted SYN to repair a lost
         * one with.
         */
        boolean replied;

        Flow(int protocol, long egress, long registration, long nowMs) {
            this.protocol = protocol;
            this.egress = egress;
            this.registration = registration;
            this.lastSeenMs = nowMs;
        }

        /** Records one packet on the flow, in either direction. */
        void note(int tcpFlags, boolean outbound, long nowMs) {
            lastSeenMs = nowMs;
            if (protocol != PeerEgressSegment.IPV4_PROTOCOL_TCP) {
                return;
            }
            if ((tcpFlags & PeerEgressSegment.FLAG_RST) != 0 && !closed) {
                closed = true;
                closedAtMs = nowMs;
            }
            if ((tcpFlags & PeerEgressSegment.FLAG_FIN) != 0) {
                if (outbound) {
                    finOut = true;
                } else {
                    finIn = true;
                }
            }
            // One FIN is a half close, after which the other side may go on sending for as long as
            // it likes; only both together end the connection.
            if (finOut && finIn && !closed) {
                closed = true;
                closedAtMs = nowMs;
            }
        }

        /** The first moment at which the flow is forgotten. */
        long deadlineMs() {
            if (protocol != PeerEgressSegment.IPV4_PROTOCOL_TCP) {
                return lastSeenMs + UDP_IDLE_MS;
            }
            return closed ? closedAtMs + TCP_CLOSED_LINGER_MS : lastSeenMs + TCP_IDLE_MS;
        }

        /**
         * Records where the application is on a TCP flow from a segment it sent. Read from the
         * header directly rather than through the parser: this runs on every forwarded packet, and
         * a checksum over the whole segment for two numbers would be paid on every one.
         */
        void noteApplicationProgress(byte[] packet) {
            int ihl = (packet[0] & 0x0f) * 4;
            if (packet.length < ihl + 20) {
                return;
            }
            int dataOffset = ((packet[ihl + 12] & 0xff) >>> 4) * 4;
            if (dataOffset < 20) {
                return;
            }
            int total = Math.min(((packet[2] & 0xff) << 8) | (packet[3] & 0xff), packet.length);
            int payload = Math.max(total - ihl - dataOffset, 0);
            int flags = packet[ihl + 13] & 0xff;
            int next = readInt(packet, ihl + 4) + payload;
            if ((flags & PeerEgressSegment.FLAG_SYN) != 0) {
                next++;
            }
            if ((flags & PeerEgressSegment.FLAG_FIN) != 0) {
                next++;
            }
            appSeqNext = next;
            if ((flags & PeerEgressSegment.FLAG_ACK) != 0) {
                appAck = readInt(packet, ihl + 8);
                appAckKnown = true;
            }
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

    /**
     * Kept in the order packets were last seen, oldest first: every packet moves its flow to the
     * end. That puts the flow to evict when the table is full at the head, rather than at the end of
     * a walk over up to {@link #DEFAULT_FLOW_CAPACITY} entries for every new flow.
     */
    private final LinkedHashMap<PeerEgressFlowTable.Key, Flow> flows = new LinkedHashMap<>();
    private final int flowCapacity;
    private long registrations;
    /**
     * No entry lapses before this. A lower bound rather than the exact moment, so that a packet
     * which moves a deadline later costs nothing; a deadline that moves earlier (a new flow, or a
     * TCP close) lowers it. While it lies ahead, a full table holds only live flows and no walk is
     * needed to know it.
     */
    private long nextExpiryMs = Long.MAX_VALUE;
    private long lastSweepMs;
    private final Map<String, Long> blocked = new TreeMap<>();

    /**
     * Phase two (protocol/spec/peer-egress-dns.md): the fake-IP pool while it runs, null while it
     * does not. A destination inside it is steered by the name it was handed out for.
     */
    private PeerEgressFakeIpPool fakeIps;
    /** The egresses the catalogue says resolve names; any other gets no traffic for a name. */
    private Set<Long> domainCapable = Set.of();
    /** Phase two's DNS responder, which takes port 53 of the pool's listen address; or null. */
    private PeerEgressDnsResponder dnsResponder;
    /** This node's mesh address, parsed: the source a local DNS query normally has. */
    private Integer virtualAddress;
    /**
     * Whether an address is one of this machine's interfaces', the other source a local query may
     * have. Supplied by the mesh, which caches the interface list; only this node's mesh address
     * counts without it.
     */
    private java.util.function.IntPredicate localAddress = address -> false;

    PeerEgressConsumer(Sender sender, TunWriter tunWriter) {
        this(sender, tunWriter, DEFAULT_FLOW_CAPACITY);
    }

    /** With a smaller table, so a test can fill it. */
    PeerEgressConsumer(Sender sender, TunWriter tunWriter, int flowCapacity) {
        this.sender = sender;
        this.tunWriter = tunWriter;
        this.flowCapacity = Math.max(1, flowCapacity);
    }

    /**
     * What an operator can read, for the status surface.
     *
     * <p>No lock here, for the same reason nothing else in this class has one: the caller
     * serialises access. Copies of the collections, because the caller is a diagnostic reader and
     * this consumer goes on mutating its own. Lapsed flows are swept first, so the count is of the
     * flows still remembered.
     */
    PeerEgressStatus.ConsumerSnapshot statusSnapshot(long nowMs) {
        sweep(nowMs);
        Map<Long, Integer> byEgress = new java.util.TreeMap<>();
        for (Flow flow : flows.values()) {
            byEgress.merge(flow.egress, 1, Integer::sum);
        }
        PeerEgressFakeIpPool pool = fakeIps;
        return new PeerEgressStatus.ConsumerSnapshot(List.copyOf(rules), meshCidr,
                new java.util.LinkedHashMap<>(online), flows.size(),
                new java.util.TreeMap<>(blocked), byEgress, Map.of(),
                pool == null ? null : pool.cidr(), domainCapable,
                pool == null ? 0 : pool.mappings(), pool == null ? 0 : pool.quarantined(nowMs));
    }

    /**
     * Installs a rule set and closes the flows it invalidates, with phase two not running.
     *
     * <p>Established flows survive a rule change unless their rule stopped saying egress or stopped
     * matching. The returned purge messages tell each affected egress to close its side; without
     * them the egress would hold the socket until its own idle timer, and the user would see a
     * connection that is dead at one end and open at the other.
     */
    Map<Long, List<String>> configure(
            List<PeerEgressRule> newRules, String newMeshCidr, String newVirtualIp, long nowMs) {
        return configure(newRules, newMeshCidr, newVirtualIp, null, nowMs);
    }

    /**
     * As above, with the fake-IP pool while phase two runs, or null. The rules are validated against
     * it, which is what puts domain rules in force and takes address rules reaching into it out.
     */
    Map<Long, List<String>> configure(List<PeerEgressRule> newRules, String newMeshCidr,
            String newVirtualIp, PeerEgressFakeIpPool pool, long nowMs) {
        return configure(newRules, newMeshCidr, newVirtualIp, pool, null, nowMs);
    }

    /** As above, with the DNS responder that answers from the pool (step four), or null. */
    Map<Long, List<String>> configure(List<PeerEgressRule> newRules, String newMeshCidr,
            String newVirtualIp, PeerEgressFakeIpPool pool, PeerEgressDnsResponder responder, long nowMs) {
        rules = newRules == null ? List.of() : List.copyOf(newRules);
        if (newMeshCidr != null && !newMeshCidr.trim().isEmpty()) {
            meshCidr = newMeshCidr.trim();
        }
        virtualIp = newVirtualIp == null ? "" : newVirtualIp.trim();
        virtualAddress = Ipv4Cidr.parseAddress(virtualIp);
        fakeIps = pool;
        dnsResponder = pool == null ? null : responder;
        return purgeInvalidated(nowMs);
    }

    /** How to tell this machine's interface addresses, for the DNS responder's source check. */
    void setLocalAddresses(java.util.function.IntPredicate addresses) {
        localAddress = addresses == null ? address -> false : addresses;
    }

    /**
     * Records which egresses the catalogue says resolve names, and closes the flows to a fake
     * address whose egress no longer does. A flow to an address is unaffected: it asks the egress
     * for nothing but the address.
     */
    Map<Long, List<String>> setDomainCapable(Set<Long> capable, long nowMs) {
        Set<Long> next = capable == null ? Set.of() : Set.copyOf(capable);
        if (next.equals(domainCapable)) {
            return Map.of();
        }
        domainCapable = next;
        return purgeInvalidated(nowMs);
    }

    /** The pool phase two runs with, or null; the DNS responder answers from the same one. */
    PeerEgressFakeIpPool fakeIpPool() {
        return fakeIps;
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
        // A flow already forgotten is not reset or purged: whether it was would otherwise depend on
        // whether a sweep had happened to run since it lapsed.
        sweep(nowMs);
        Map<Long, TreeSet<String>> purge = new TreeMap<>();
        List<PeerEgressFlowTable.Key> dropped = new ArrayList<>();
        List<byte[]> resets = new ArrayList<>();
        PeerEgressFakeIpPool pool = fakeIps;
        for (Map.Entry<PeerEgressFlowTable.Key, Flow> entry : flows.entrySet()) {
            PeerEgressFlowTable.Key key = entry.getKey();
            Flow flow = entry.getValue();
            boolean stillOurs;
            if (pool != null && pool.contains(key.remoteIp())) {
                // The same decision a packet gets, from the name the address stands for, but
                // without refreshing the mapping: a rule change is not traffic.
                String name = pool.nameOf(key.remoteIp());
                PeerEgressRule rule = name == null ? null : domainRuleFor(name);
                stillOurs = rule != null
                        && PeerEgressRule.ACTION_EGRESS.equals(actionOf(rule))
                        && Long.valueOf(flow.egress).equals(rule.getEgressClientId())
                        && Boolean.TRUE.equals(online.get(flow.egress))
                        && domainCapable.contains(flow.egress);
            } else {
                PeerEgressRules.Match match = PeerEgressRules.match(
                        rules, Ipv4Cidr.format(key.remoteIp()), meshCidr, poolCidr());
                stillOurs = PeerEgressRule.ACTION_EGRESS.equals(match.action())
                        && match.egressClientId() != null
                        && match.egressClientId() == flow.egress
                        && Boolean.TRUE.equals(online.get(flow.egress));
            }
            if (stillOurs) {
                continue;
            }
            dropped.add(key);
            purge.computeIfAbsent(flow.egress, unused -> new TreeSet<>())
                    .add(Ipv4Cidr.format(key.remoteIp()) + "/32");
            byte[] reset = flowResetPacket(key, flow);
            if (reset != null) {
                resets.add(reset);
            }
        }
        for (PeerEgressFlowTable.Key key : dropped) {
            flows.remove(key);
        }
        // The application is told each flow is over, so it fails now rather than at its own
        // timeout; the egress is told through the purge messages returned.
        if (tunWriter != null) {
            for (byte[] reset : resets) {
                tunWriter.write(reset);
            }
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

        int protocol = PeerIpPacket.protocol(packet);
        int address = readInt(packet, 16);
        PeerEgressFakeIpPool pool = fakeIps;
        PeerEgressDnsResponder responder = dnsResponder;
        if (responder != null && address == responder.listenAddress() && isDnsPort(packet, protocol)) {
            // The responder's own port, ahead of any steering. Only this machine is answered: a
            // query from anywhere else means this node is forwarding for somebody, and phase two
            // resolves for nobody but itself. Other ports of the listen address fall through to
            // the pool, which has no mapping for it.
            int source = readInt(packet, 12);
            if ((virtualAddress == null || source != virtualAddress) && !localAddress.test(source)) {
                recordBlocked("dns-not-local");
                return Outcome.BLOCKED_NOT_LOCAL;
            }
            responder.handle(packet, protocol, rules, meshCidr, nowMs);
            return Outcome.DNS;
        }
        // The name a fake address stands for, when the destination is one; null for an address.
        String name = null;
        Long egress;
        if (pool != null && pool.contains(address)) {
            // Steered by the name the address was handed out for, never by an address rule:
            // validation keeps address rules out of the pool. The responder's own address, the
            // network and the broadcast address are never mapped, so they land in the first case;
            // the responder claims its own port 53 before this is reached (step four).
            name = pool.traffic(address, nowMs);
            if (name == null) {
                // The one real leak point of fake-IP. An address that stands for no name has no
                // right destination: sent to an egress or let out locally, the traffic would go
                // where no rule said.
                return refuseAnswered(packet, protocol, "fake-ip-unmapped", Outcome.BLOCKED_FAKE_IP);
            }
            PeerEgressRule rule = domainRuleFor(name);
            if (rule == null || PeerEgressRule.ACTION_DIRECT.equals(actionOf(rule))) {
                // The name was handed out under rules that no longer claim it. Its real address is
                // unknown here, so the only choices are to block or to guess; answered, the
                // application asks again, and the fresh query goes where the rules now say.
                return refuseAnswered(packet, protocol, "fake-ip-stale", Outcome.BLOCKED_FAKE_IP);
            }
            if (PeerEgressRule.ACTION_BLOCK.equals(actionOf(rule))) {
                recordBlocked("rule");
                return Outcome.BLOCKED_BY_RULE;
            }
            egress = rule.getEgressClientId();
        } else {
            PeerEgressRules.Match match = PeerEgressRules.match(rules, destination, meshCidr, poolCidr());
            if (!match.matched()
                    || (!PeerEgressRule.ACTION_EGRESS.equals(match.action())
                            && !PeerEgressRule.ACTION_BLOCK.equals(match.action()))) {
                return Outcome.NOT_MINE;
            }
            if (PeerEgressRule.ACTION_BLOCK.equals(match.action())) {
                recordBlocked("rule");
                return Outcome.BLOCKED_BY_RULE;
            }
            egress = match.egressClientId();
        }

        if (protocol != PeerEgressSegment.IPV4_PROTOCOL_TCP
                && protocol != PeerEgressDatagram.IPV4_PROTOCOL_UDP) {
            // ICMP and anything else this version does not carry. The rule says this destination
            // must not go out locally, so it is dropped rather than handed back.
            recordBlocked("unsupported-protocol");
            return Outcome.UNSUPPORTED;
        }
        if (egress == null || !Boolean.TRUE.equals(online.get(egress))) {
            // Answered, not just dropped. The rule is doing what it should, but the application
            // would only learn that from its own timeout; a reset or an unreachable lets it fail
            // now and retry when the egress is back. A failed send, by contrast, stays silent:
            // the session may be re-establishing and the flow may yet recover.
            return refuseAnswered(packet, protocol, "egress-unavailable", Outcome.BLOCKED_NO_EGRESS);
        }
        if (name != null && !domainCapable.contains(egress)) {
            // Online, but the catalogue does not say it resolves names: a name sent to it would be
            // refused there. Not resolved locally instead, which would be the leak. Usually the
            // moment between the egress coming online and its catalogue entry arriving.
            return refuseAnswered(packet, protocol, "egress-no-domain", Outcome.BLOCKED_NO_EGRESS);
        }

        PeerEgressFlowTable.Key key = flowKeyFor(packet, protocol);
        int tcpFlags = tcpFlags(packet);
        boolean fresh = false;
        Flow flow = null;
        if (key != null) {
            sweepIfDue(nowMs);
            flow = liveFlow(key, nowMs);
            if (flow != null && flow.closed
                    && (tcpFlags & (PeerEgressSegment.FLAG_SYN | PeerEgressSegment.FLAG_ACK))
                            == PeerEgressSegment.FLAG_SYN) {
                // A SYN on a four-tuple whose connection has closed is a new connection reusing
                // the port. Folding it into the old entry would leave it forgotten when the old
                // one's linger ends, and its replies refused.
                flows.remove(key);
                flow = null;
            }
            if (flow == null) {
                makeRoom(nowMs);
                flow = new Flow(protocol, egress, ++registrations, nowMs);
                fresh = true;
            }
            touch(key, flow, tcpFlags, true, nowMs);
            if (protocol == PeerEgressSegment.IPV4_PROTOCOL_TCP) {
                flow.noteApplicationProgress(packet);
            }
        }

        if (sender == null) {
            return Outcome.BLOCKED_NO_EGRESS;
        }
        if (name != null && needsNameBind(protocol, tcpFlags, fresh, flow)
                && !sender.send(egress, PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false,
                        PeerEgressFrame.encodeControl(PeerEgressFrame.Control.nameBind(destination, name))))) {
            // Ahead of the packet, so the egress knows the name when the flow reaches it. One that
            // did not go takes the packet with it: sent anyway, the egress could only open a flow to
            // the fake address itself. Silent, like any failed send; the flow stays registered, so
            // the retransmitted SYN or the next datagram carries a name-bind again.
            recordBlocked("send-failed");
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
     * Whether a packet to a fake address goes with a name-bind: it opened a flow here, it is a TCP
     * SYN without ACK (a retransmitted one included), or its UDP flow has not heard from the egress
     * yet. Control messages are unreliable, so one is not enough; TCP repairs a lost one with the
     * SYN the application retransmits, and UDP, which retransmits nothing of its own, with every
     * datagram until the egress answers. A packet whose flow cannot be tracked carries one too.
     */
    private static boolean needsNameBind(int protocol, int tcpFlags, boolean fresh, Flow flow) {
        if (fresh || flow == null) {
            return true;
        }
        if (protocol == PeerEgressSegment.IPV4_PROTOCOL_TCP) {
            return (tcpFlags & (PeerEgressSegment.FLAG_SYN | PeerEgressSegment.FLAG_ACK))
                    == PeerEgressSegment.FLAG_SYN;
        }
        return !flow.replied;
    }

    /** Whether a TCP or UDP packet is addressed to port 53. */
    private static boolean isDnsPort(byte[] packet, int protocol) {
        if (protocol != PeerEgressSegment.IPV4_PROTOCOL_TCP && protocol != PeerEgressDatagram.IPV4_PROTOCOL_UDP) {
            return false;
        }
        int ihl = (packet[0] & 0x0f) * 4;
        return ihl >= IPV4_MIN_HEADER_BYTES && packet.length >= ihl + 4
                && readShort(packet, ihl + 2) == PeerEgressDnsResponder.PORT;
    }

    /**
     * Counts a refusal and answers it the way an unreachable host would, so the application fails
     * now instead of at its own timeout.
     */
    private Outcome refuseAnswered(byte[] packet, int protocol, String reason, Outcome outcome) {
        recordBlocked(reason);
        byte[] answer = failurePacket(packet, protocol);
        if (answer != null && tunWriter != null) {
            tunWriter.write(answer);
        }
        return outcome;
    }

    /**
     * The domain rule that claims a name, or null. A rule whose egress cannot resolve names still
     * claims its names; the traffic then counts as egress-no-domain rather than going local.
     */
    private PeerEgressRule domainRuleFor(String name) {
        Integer index = PeerEgressDns.selectDomainRule(rules, name, meshCidr, poolCidr());
        return index == null ? null : rules.get(index);
    }

    /** The pool phase two runs with, as text, or null while it does not. */
    private String poolCidr() {
        PeerEgressFakeIpPool pool = fakeIps;
        return pool == null ? null : pool.cidr();
    }

    private static String actionOf(PeerEgressRule rule) {
        return rule.getAction() == null ? "" : rule.getAction().trim();
    }

    /**
     * Answers a packet the consumer refused to forward, the way an unreachable host would: a TCP
     * reset placed where the application's stack accepts it (RFC 793), or an ICMP host-unreachable
     * for a datagram. Null when there is nothing an application could act on. Shared vector:
     * {@code protocol/test-vectors/peer-egress-failure-v1.json}.
     */
    static byte[] failurePacket(byte[] packet, int protocol) {
        if (protocol == PeerEgressSegment.IPV4_PROTOCOL_TCP) {
            PeerEgressSegment.Segment segment = PeerEgressSegment.parse(packet);
            return segment == null ? null : PeerEgressSegment.buildReset(segment);
        }
        if (protocol == PeerEgressDatagram.IPV4_PROTOCOL_UDP) {
            return PeerIpPacket.icmpHostUnreachableFor(packet);
        }
        return null;
    }

    /**
     * The reset for a flow the consumer closed, or null when there is none to build: a datagram
     * flow, or a TCP flow on which the application has not yet sent an acknowledgement, whose
     * retransmitted SYN will be answered when it arrives.
     */
    private static byte[] flowResetPacket(PeerEgressFlowTable.Key key, Flow flow) {
        if (key.protocol() != PeerEgressSegment.IPV4_PROTOCOL_TCP || !flow.appAckKnown) {
            return null;
        }
        return PeerEgressSegment.build(new PeerEgressSegment.Segment(
                key.remoteIp(), key.consumerIp(), key.remotePort(), key.consumerPort(),
                flow.appAck, flow.appSeqNext, PeerEgressSegment.FLAG_RST | PeerEgressSegment.FLAG_ACK,
                0, 0, new byte[0]));
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

    /** The flags of an IPv4 TCP segment, or none for anything else or a header cut short. */
    private static int tcpFlags(byte[] packet) {
        if (packet.length < IPV4_MIN_HEADER_BYTES
                || (packet[9] & 0xff) != PeerEgressSegment.IPV4_PROTOCOL_TCP) {
            return 0;
        }
        int ihl = (packet[0] & 0x0f) * 4;
        if (ihl < IPV4_MIN_HEADER_BYTES || packet.length < ihl + 14) {
            return 0;
        }
        return packet[ihl + 13] & 0xff;
    }

    /**
     * The flow for a four-tuple if it is still remembered. One that has lapsed is removed on the
     * way, so a lookup never depends on whether a sweep has run since.
     */
    private Flow liveFlow(PeerEgressFlowTable.Key key, long nowMs) {
        Flow flow = flows.get(key);
        if (flow != null && nowMs >= flow.deadlineMs()) {
            flows.remove(key);
            return null;
        }
        return flow;
    }

    /** Records a packet on a flow, registering the flow if it is new. */
    private void touch(PeerEgressFlowTable.Key key, Flow flow, int tcpFlags, boolean outbound, long nowMs) {
        flow.note(tcpFlags, outbound, nowMs);
        flows.putLast(key, flow);
        nextExpiryMs = Math.min(nextExpiryMs, flow.deadlineMs());
    }

    /**
     * Frees one entry for a new flow when the table is full, by forgetting the flow that has gone
     * longest without a packet.
     *
     * <p>Only live flows fill the table, so lapsed ones are swept first when any may have lapsed.
     * The map's order is the order of last packets, so the candidates are the run at its head that
     * share the oldest time; of those, the one registered first goes. With a clock that stepped
     * back the head is no longer strictly the oldest, but it is still the least recently seen.
     */
    private void makeRoom(long nowMs) {
        if (flows.size() < flowCapacity) {
            return;
        }
        if (nowMs >= nextExpiryMs) {
            sweep(nowMs);
        }
        while (flows.size() >= flowCapacity) {
            Map.Entry<PeerEgressFlowTable.Key, Flow> victim = null;
            for (Map.Entry<PeerEgressFlowTable.Key, Flow> entry : flows.entrySet()) {
                if (victim == null) {
                    victim = entry;
                } else if (entry.getValue().lastSeenMs != victim.getValue().lastSeenMs) {
                    break;
                } else if (entry.getValue().registration < victim.getValue().registration) {
                    victim = entry;
                }
            }
            flows.remove(victim.getKey());
        }
    }

    /** Walks the table only when an entry may have lapsed, and not more than once a second. */
    private void sweepIfDue(long nowMs) {
        if (nowMs >= nextExpiryMs && (nowMs - lastSweepMs >= SWEEP_INTERVAL_MS || nowMs < lastSweepMs)) {
            sweep(nowMs);
        }
    }

    /** Removes every lapsed flow, which releases its memory, and learns the next deadline exactly. */
    private void sweep(long nowMs) {
        long next = Long.MAX_VALUE;
        for (var iterator = flows.values().iterator(); iterator.hasNext(); ) {
            long deadline = iterator.next().deadlineMs();
            if (nowMs >= deadline) {
                iterator.remove();
            } else {
                next = Math.min(next, deadline);
            }
        }
        nextExpiryMs = next;
        lastSweepMs = nowMs;
    }

    /** Whether the flow for a four-tuple is still remembered. Changes nothing. */
    boolean remembers(PeerEgressFlowTable.Key key, long nowMs) {
        Flow flow = flows.get(key);
        return flow != null && nowMs < flow.deadlineMs();
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
            handleFlowReject(control, fromEgress, nowMs);
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
        if (!hasReturnFlow(parsed.inner(), parsed.body(), fromEgress, nowMs)) {
            recordBlocked("return-no-flow");
            return true;
        }
        if (tunWriter != null) {
            tunWriter.write(parsed.body());
        }
        return true;
    }

    /**
     * Reports whether a reply belongs to a flow this node opened through this egress and still
     * remembers, and records it on that flow. The tuple is mirrored, since the reply travels the
     * other way.
     */
    private boolean hasReturnFlow(PeerEgressFrame.Inner inner, byte[] packet, long fromEgress, long nowMs) {
        Integer remote = Ipv4Cidr.parseAddress(inner.sourceIp());
        Integer local = Ipv4Cidr.parseAddress(inner.destinationIp());
        if (remote == null || local == null) {
            return false;
        }
        sweepIfDue(nowMs);
        var key = new PeerEgressFlowTable.Key(
                inner.protocol(), local, inner.destinationPort(), remote, inner.sourcePort());
        Flow flow = liveFlow(key, nowMs);
        if (flow == null || flow.egress != fromEgress) {
            return false;
        }
        // The egress has the flow, so it had the name: a datagram after this needs no name-bind.
        flow.replied = true;
        touch(key, flow, tcpFlags(packet), false, nowMs);
        return true;
    }

    /**
     * A rejection can overtake (or survive loss of) the remote RST. Reset locally before forgetting
     * the flow, and only accept its actual egress as the sender.
     */
    private void handleFlowReject(PeerEgressFrame.Control control, long fromEgress, long nowMs) {
        Integer remote = Ipv4Cidr.parseAddress(control.destinationIp());
        Integer local = Ipv4Cidr.parseAddress(control.sourceIp());
        if (remote == null || local == null) {
            return;
        }
        var key = new PeerEgressFlowTable.Key(protocolNumberFor(control.protocol()),
                local, control.sourcePort(), remote, control.destinationPort());
        // A flow already forgotten has nothing left to reset.
        Flow flow = liveFlow(key, nowMs);
        if (flow == null || flow.egress != fromEgress) {
            return;
        }
        byte[] reset = flowResetPacket(key, flow);
        flows.remove(key);
        recordBlocked("rejected-" + control.code().toLowerCase(Locale.ROOT));
        if (reset != null && tunWriter != null) {
            tunWriter.write(reset);
        }
        log.info("[peer-egress-consumer] egress={} refused flow code={}", fromEgress, control.code());
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

    /**
     * The entries held in memory, including any that have lapsed and not yet been swept. The count
     * an operator reads is {@link #statusSnapshot}'s, which sweeps first.
     */
    int flowCount() {
        return flows.size();
    }
}
