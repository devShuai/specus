package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import com.theshuai.common.peeregress.PeerEgressRequest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * The egress flow table: what is open right now, who opened it, and when it stops being allowed.
 *
 * <p>TCP announces its own beginning and end, so its state machine could in principle track itself.
 * UDP announces neither, so a session exists only because this table says it does, and ends only
 * because an idle timer says it does. Both protocols share one table anyway, because the limits in
 * the policy count flows rather than TCP flows: a consumer must not be able to exceed its quota by
 * splitting traffic across protocols.
 *
 * <p>Like the TCP state machine this holds no sockets and reads no clock. Time arrives as an
 * argument so expiry is deterministic under test, and the caller keeps whatever handle it needs in
 * {@link Flow#handle}, which this class never inspects.
 *
 * <p>Not safe for concurrent use. The data plane serialises access through its own loop, and a lock
 * here would invite callers to hold a flow past the point where the table still vouches for it.
 */
final class PeerEgressFlowTable {

    /** Applies when the policy names no timeout. Long enough not to cut a QUIC connection between
     * its own keepalives, short enough that a consumer that vanished stops holding a socket. */
    static final long DEFAULT_IDLE_TIMEOUT_MS = 5 * 60 * 1000L;

    /**
     * Identifies one flow by its full inner four-tuple.
     *
     * <p>Keying on the consumer's source port alone would be wrong, not merely coarse. Two
     * datagrams leaving the same consumer port for different destinations are separate sessions;
     * collapsing them onto one socket would send the second destination's traffic to the first.
     */
    record Key(int protocol, int consumerIp, int consumerPort, int remoteIp, int remotePort) {

        String protocolName() {
            return switch (protocol) {
                case PeerEgressSegment.IPV4_PROTOCOL_TCP -> "tcp";
                case PeerEgressDatagram.IPV4_PROTOCOL_UDP -> "udp";
                // Anything else yields a name no destination rule can match, so an unsupported
                // protocol is refused rather than defaulting to one a rule might allow.
                default -> "";
            };
        }
    }

    /** One live flow's accounting. The data plane owns the socket; this owns the fact that it may exist. */
    static final class Flow {
        final Key key;
        final long consumer;
        final long openedAtMs;
        long lastSeenMs;
        long bytesToRemote;
        long bytesFromRemote;

        /**
         * A TCP flow in TIME_WAIT: its socket is closed and it no longer counts against the limits,
         * but the entry stays until the timer so a retransmitted FIN is still answered.
         */
        boolean lingering;

        /**
         * The (normalised) name the consumer had bound to the remote address when this flow was
         * opened, or null for a flow to the address itself. A name-bind that says otherwise closes
         * the flow: it went somewhere other than where the name now says.
         */
        String name;

        /**
         * The address the socket was dialled to. The key's remote address for a flow to an address;
         * for a flow to a name, the resolved address it was authorised for, while the key keeps the
         * consumer's fake address. Re-authorization judges this one, as the opening did.
         */
        String address;

        /**
         * Whatever the caller attached: a connection, a socket, a cancellation handle. Stored so
         * that everything needed to tear a flow down travels with the entry that authorises it, and
         * never read here.
         */
        Object handle;

        Flow(Key key, long consumer, long nowMs) {
            this.key = key;
            this.consumer = consumer;
            this.openedAtMs = nowMs;
            this.lastSeenMs = nowMs;
            this.address = Ipv4Cidr.format(key.remoteIp());
        }
    }

    /**
     * Pairs a closed flow with why it closed.
     *
     * <p>Carried per flow rather than per batch because one policy push can close flows for
     * different reasons at once: a destination rule dropped for one, a consumer removed from the
     * allow list for another. Collapsing them onto a single code would put a reason in the
     * consumer's flow-reject that does not match what actually happened to that flow.
     */
    record Revocation(Flow flow, String code) {
    }

    private long idleTimeoutMs;
    private final Map<Key, Flow> flows = new LinkedHashMap<>();
    /** perConsumer and lingering together account for every entry: a flow counts in exactly one. */
    private final Map<Long, Integer> perConsumer = new LinkedHashMap<>();
    private int lingering;

    PeerEgressFlowTable(long idleTimeoutMs) {
        setIdleTimeoutMs(idleTimeoutMs);
    }

    /**
     * Adopts the timeout a pushed policy names. Live flows keep their entries and are measured
     * against the new value from the next expiry sweep, because a policy change is not a reason to
     * close a flow that the policy still allows.
     */
    void setIdleTimeoutMs(long value) {
        this.idleTimeoutMs = value > 0 ? value : DEFAULT_IDLE_TIMEOUT_MS;
    }

    /** The live flows; a flow lingering in TIME_WAIT is not one. */
    int size() {
        return flows.size() - lingering;
    }

    /**
     * Moves a flow out of the limits for the rest of its TIME_WAIT. A consumer that finished 64 short
     * connections could otherwise open no more for the ten seconds they linger. Idempotent.
     */
    void linger(Flow flow) {
        if (flow.lingering || flows.get(flow.key) != flow) {
            return;
        }
        flow.lingering = true;
        lingering++;
        release(flow.consumer);
    }

    /** The timeout in force, which a pushed policy can change. */
    long idleTimeoutMs() {
        return idleTimeoutMs;
    }

    /**
     * The live flows, for a caller that has to walk them. Returned as a copy so the caller can
     * close entries while iterating.
     */
    List<Flow> live() {
        return new ArrayList<>(flows.values());
    }

    /** Feeds the two limit checks in the judgment layer, so it excludes the flow being considered. */
    int countFor(long consumer) {
        return perConsumer.getOrDefault(consumer, 0);
    }

    Flow lookup(Key key) {
        return flows.get(key);
    }

    /** Idle expiry is measured from the last packet in either direction, so a flow that is only
     * receiving stays alive. */
    void touch(Key key, long nowMs) {
        Flow flow = flows.get(key);
        if (flow != null) {
            flow.lastSeenMs = nowMs;
        }
    }

    /**
     * Records an authorised flow, returning null when the key is already present.
     *
     * <p>A caller must treat that as "use the existing flow" rather than as an error: a
     * retransmitted SYN, or a second datagram arriving before the first finished opening, is normal
     * traffic and not an attack.
     */
    Flow open(Key key, long consumer, long nowMs) {
        Flow existing = flows.get(key);
        if (existing != null) {
            existing.lastSeenMs = nowMs;
            return null;
        }
        Flow flow = new Flow(key, consumer, nowMs);
        flows.put(key, flow);
        perConsumer.merge(consumer, 1, Integer::sum);
        return flow;
    }

    /** Removes a flow and returns it so the caller can release the socket it carries. Closing an
     * unknown key is not an error; teardown races are ordinary. */
    Flow close(Key key) {
        Flow flow = flows.remove(key);
        if (flow != null) {
            forget(flow);
        }
        return flow;
    }

    /** Takes a removed flow out of whichever count holds it. */
    private void forget(Flow flow) {
        if (flow.lingering) {
            lingering--;
        } else {
            release(flow.consumer);
        }
    }

    private void release(long consumer) {
        Integer remaining = perConsumer.get(consumer);
        if (remaining == null) {
            return;
        }
        if (remaining <= 1) {
            // Dropping the entry rather than leaving a zero keeps the map bounded by live consumers
            // instead of by every consumer that ever connected.
            perConsumer.remove(consumer);
        } else {
            perConsumer.put(consumer, remaining - 1);
        }
    }

    /** Removes every flow idle for longer than the timeout. Without this a UDP session would never
     * end, because nothing in UDP says it has. */
    List<Flow> expire(long nowMs) {
        return reap(flow -> nowMs - flow.lastSeenMs >= idleTimeoutMs);
    }

    /** Closes every flow belonging to one consumer, for the moment its authorization is withdrawn.
     * A revoked consumer must stop being forwarded immediately, not when it next opens something. */
    List<Flow> revokeConsumer(long consumer) {
        return reap(flow -> flow.consumer == consumer);
    }

    /** Closes everything, for egress shutdown or for the tenant switch being turned off. */
    List<Flow> drain() {
        return reap(flow -> true);
    }

    /**
     * Closes every flow of one consumer whose remote address falls inside one of the given
     * prefixes, which serves the flow-purge control message.
     *
     * <p>Scoped to its sender: a purge arrives over one consumer's session and speaks only for that
     * consumer, so applying it to everyone would let any peer tear down every other peer's traffic
     * with one message. A consumer of zero means no restriction, which is for local teardown rather
     * than for anything that arrives on the wire.
     *
     * <p>An unparseable prefix is skipped rather than treated as matching everything: a malformed
     * purge should close nothing, not the whole table.
     */
    List<Flow> purgeDestinations(long consumer, List<String> destinations) {
        List<Ipv4Cidr> prefixes = new ArrayList<>();
        if (destinations != null) {
            for (String text : destinations) {
                Ipv4Cidr cidr = Ipv4Cidr.parse(text);
                if (cidr != null) {
                    prefixes.add(cidr);
                }
            }
        }
        if (prefixes.isEmpty()) {
            return List.of();
        }
        return reap(flow -> {
            if (consumer != 0 && flow.consumer != consumer) {
                return false;
            }
            for (Ipv4Cidr prefix : prefixes) {
                if (prefix.contains(flow.key.remoteIp())) {
                    return true;
                }
            }
            return false;
        });
    }

    /**
     * Closes every flow of one consumer to one address that was not opened for this name, which
     * serves name-bind (protocol/spec/peer-egress-dns.md). A flow opened before the name arrived
     * went to the fake address itself and can never work, yet the consumer's retransmitted SYN or
     * next datagram would be taken as part of it; closed, the next packet opens a flow by name. A
     * flow opened for another name goes with it when the address is bound to a new one. The same
     * name bound again closes nothing.
     */
    List<Flow> closeUnbound(long consumer, int address, String name) {
        return reap(flow -> flow.consumer == consumer && flow.key.remoteIp() == address
                && !java.util.Objects.equals(flow.name, name));
    }

    /**
     * Reports whether a packet arriving from the real network belongs to a flow this node opened.
     *
     * <p>Without it a peer could inject a packet with any source address it liked and have the
     * egress relay it into the mesh as though the egress had fetched it.
     */
    boolean hasReturnPath(Key key) {
        return flows.containsKey(key);
    }

    /**
     * Runs the judgment layer again over every live flow against a policy that has just changed,
     * and returns the flows that are no longer allowed together with why.
     *
     * <p>A policy change that only governs new flows is not a revocation. An operator who deletes a
     * destination rule expects that traffic to stop, and would reasonably read a connection that
     * keeps running until its peer closes it as the rule having failed to apply.
     *
     * <p>The limit fields are deliberately not re-checked. Lowering a quota should stop the next
     * flow, not pick live ones to kill, and a limit breach is not a permission the flow lost.
     *
     * <p>A flow opened under a name is judged as it was opened: the address it was dialled to, with
     * its name, so a domain rule that admitted it keeps it and one that is gone revokes it. Judging
     * the key's fake address instead would test an address nothing was ever dialled to.
     */
    List<Revocation> reauthorize(
            PeerEgressPolicy policy,
            java.util.function.LongPredicate peerAclAllows,
            PeerEgressAuthorization.Context context,
            List<String> localInterfaceCidrs) {

        Map<Key, String> codes = new LinkedHashMap<>();
        List<Flow> reaped = reap(flow -> {
            boolean allowed = peerAclAllows == null || peerAclAllows.test(flow.consumer);
            PeerEgressRequest request = new PeerEgressRequest();
            request.setConsumerClientId(flow.consumer);
            request.setDestinationIp(flow.address);
            request.setName(flow.name);
            request.setDestinationPort(flow.key.remotePort());
            request.setProtocol(flow.key.protocolName());
            request.setLocalInterfaceCidrs(
                    localInterfaceCidrs == null ? List.of() : localInterfaceCidrs);
            PeerEgressAuthorization.Decision decision =
                    PeerEgressAuthorization.evaluate(request, policy, allowed, context);
            if (decision.allowed()) {
                return false;
            }
            codes.put(flow.key, decision.code());
            return true;
        });

        List<Revocation> revoked = new ArrayList<>(reaped.size());
        for (Flow flow : reaped) {
            revoked.add(new Revocation(flow, codes.get(flow.key)));
        }
        return revoked;
    }

    /** Labels a batch that really does share one reason, such as a shutdown or an ACL withdrawal.
     * A null code means the flow ended normally and owes the consumer no explanation. */
    static List<Revocation> revocationsFor(List<Flow> reaped, String code) {
        List<Revocation> revoked = new ArrayList<>(reaped.size());
        for (Flow flow : reaped) {
            revoked.add(new Revocation(flow, code));
        }
        return revoked;
    }

    /**
     * Removes and returns the flows a predicate selects, in a stable order.
     *
     * <p>Sorted rather than in map order because the caller emits one rejection record per closed
     * flow. Ordering that changed run to run would make those records, and any test reading them,
     * non-reproducible.
     */
    private List<Flow> reap(Predicate<Flow> selects) {
        List<Flow> reaped = new ArrayList<>();
        for (Flow flow : flows.values()) {
            if (selects.test(flow)) {
                reaped.add(flow);
            }
        }
        sort(reaped);
        for (Flow flow : reaped) {
            flows.remove(flow.key);
            forget(flow);
        }
        return reaped;
    }

    static void sort(List<Flow> entries) {
        entries.sort(Comparator
                .comparingInt((Flow flow) -> flow.key.protocol())
                .thenComparing(flow -> flow.key.consumerIp(), PeerEgressFlowTable::compareUnsigned)
                .thenComparingInt(flow -> flow.key.consumerPort())
                .thenComparing(flow -> flow.key.remoteIp(), PeerEgressFlowTable::compareUnsigned)
                .thenComparingInt(flow -> flow.key.remotePort()));
    }

    /** Addresses are unsigned; comparing them as signed ints would order 10.x above 200.x. */
    private static int compareUnsigned(Integer left, Integer right) {
        return Integer.compareUnsigned(left, right);
    }
}
