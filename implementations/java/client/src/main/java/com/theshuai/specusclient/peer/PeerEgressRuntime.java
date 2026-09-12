package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import com.theshuai.common.peeregress.PeerEgressRequest;
import java.io.Closeable;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongPredicate;
import java.util.function.LongSupplier;
import lombok.extern.slf4j.Slf4j;

/**
 * The egress data plane: the only place authorization turns into a connect.
 *
 * <p>Everything under it is pure. The TCP state machine, the datagram codec, the judgment layer and
 * the flow table hold no sockets and read no clock. This class is where they meet real ones, so it
 * is also where every resource is acquired and released, and the reason the layers below could stay
 * testable without a network.
 *
 * <p>One lock serialises the whole plane. The flow table documents that it expects a single caller,
 * and a finer lock would let a reader thread hold a flow past the moment the table stopped
 * vouching for it, which is exactly the window a revocation must not have.
 */
@Slf4j
final class PeerEgressRuntime {

    /**
     * Bounds a flow's opening connect. A consumer waiting on a black-holed destination should get a
     * reset it can act on rather than a socket held until the operating system gives up.
     */
    static final long CONNECT_TIMEOUT_MS = 10_000L;

    /**
     * Used until the mesh reports a measured one. It is the conservative value the path-MTU prober
     * starts from.
     */
    static final int DEFAULT_PATH_MTU = 1280;

    private static final int TCP_READ_BUFFER = 32 * 1024;
    private static final int UDP_READ_BUFFER = 65535;

    /**
     * The subset of a socket this plane uses. Injected so the fault-injection cases can produce
     * refusals, timeouts and mid-connection failures without a network.
     */
    interface Socket extends Closeable {
        /** Returns the byte count, or -1 at end of stream. */
        int read(byte[] buffer) throws IOException;

        void write(byte[] data) throws IOException;

        /**
         * Half-closes the write side. The consumer finished sending but still expects replies, so
         * closing both would discard a response the application is still producing.
         */
        default void closeWrite() {
        }

        @Override
        void close();
    }

    /** Opens the real outbound socket. */
    interface Dialer {
        Socket dial(String protocol, String host, int port, long timeoutMs) throws IOException;
    }

    /**
     * Delivers one SPEG1 frame to a consumer. The runtime knows consumers by client id and nothing
     * about mesh sessions or paths.
     *
     * <p>It must not block: the plane's lock is held across it, so a send that waits on anything
     * which itself needs the plane would stop every flow on this node. Queue and return.
     */
    interface Sender {
        void send(long consumer, byte[] frame);
    }

    /** Runs one reader loop. A virtual thread per flow by default, injectable for tests. */
    interface Executor {
        void run(Runnable reader);
    }

    private record TcpFlow(PeerEgressTcpConnection connection, Socket socket) {
    }

    private record UdpFlow(Socket socket) {
    }

    /** What the periodic egress-report carries, alongside the per-code refusal counts. */
    record Stats(long totalFlows, long bytesIn, long bytesOut) {
    }

    private final ReentrantLock lock = new ReentrantLock();
    private final Sender sender;
    private final Dialer dialer;
    private final Executor executor;
    private final LongSupplier clock;
    private final SecureRandom random = new SecureRandom();

    private boolean enabled;
    private PeerEgressPolicy policy = new PeerEgressPolicy();
    private PeerEgressAuthorization.Context context = PeerEgressAuthorization.Context.defaults();
    private int pathMtu = DEFAULT_PATH_MTU;

    /**
     * Reports whether the mesh still authorises this consumer. It lives outside the policy because
     * the mesh ACL and the egress policy are revoked independently.
     *
     * <p>Usually null, and that is correct rather than lax: a frame only reaches this plane over a
     * session the mesh already authenticated, and withdrawal arrives as a revokeConsumer call
     * rather than as something to poll. Polling would mean reaching for the mesh's lock from under
     * this one.
     */
    private LongPredicate peerAclAllows;

    /** The last accepted egress-config snapshot. */
    private long revision;

    /**
     * The networks this host owns. Forwarding into one would loop back into this node's own capture
     * path.
     */
    private List<String> localInterfaces = List.of();

    private final PeerEgressFlowTable flows = new PeerEgressFlowTable(0);
    private final PeerEgressRejectionLog rejections = new PeerEgressRejectionLog();
    private long totalFlows;
    private long bytesIn;
    private long bytesOut;
    private boolean closed;

    PeerEgressRuntime(Sender sender, Dialer dialer) {
        this(sender, dialer, reader -> Thread.ofVirtual().start(reader), System::currentTimeMillis);
    }

    PeerEgressRuntime(Sender sender, Dialer dialer, Executor executor, LongSupplier clock) {
        this.sender = sender;
        this.dialer = dialer;
        this.executor = executor;
        this.clock = clock;
    }

    Stats stats() {
        lock.lock();
        try {
            return new Stats(totalFlows, bytesIn, bytesOut);
        } finally {
            lock.unlock();
        }
    }

    /**
     * What an operator can read about this node serving as an egress.
     *
     * <p>The refusal counts come from the cumulative tally rather than the one the periodic report
     * drains, so the numbers do not start shrinking on their own the day that report is wired up.
     */
    PeerEgressStatus.RuntimeSnapshot statusSnapshot() {
        lock.lock();
        try {
            return new PeerEgressStatus.RuntimeSnapshot(enabled, revision, flows.size(),
                    new Stats(totalFlows, bytesIn, bytesOut), rejections.cumulativeCounts());
        } finally {
            lock.unlock();
        }
    }

    int flowCount() {
        lock.lock();
        try {
            return flows.size();
        } finally {
            lock.unlock();
        }
    }

    PeerEgressRejectionLog rejections() {
        return rejections;
    }

    void setPeerAclAllows(LongPredicate predicate) {
        lock.lock();
        try {
            peerAclAllows = predicate;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Installs a pushed policy and closes whatever it no longer allows.
     *
     * <p>Both gates are off by default, so a runtime that has received nothing forwards nothing.
     * Turning the switch off drains every flow rather than waiting for idle expiry: an operator who
     * disables the egress means now.
     */
    void applyPolicy(PeerEgressPolicy newPolicy, PeerEgressAuthorization.Context newContext, long nowMs) {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            policy = newPolicy;
            context = newContext;
            enabled = newPolicy != null && newPolicy.isEnabled();
            flows.setIdleTimeoutMs(idleTimeoutFor(newPolicy));

            if (!enabled) {
                releaseAll(PeerEgressFlowTable.revocationsFor(flows.drain(), PeerEgressCodes.DISABLED), nowMs);
                return;
            }
            releaseAll(flows.reauthorize(newPolicy, peerAclAllows, context, localInterfaces), nowMs);
        } finally {
            lock.unlock();
        }
    }

    private static long idleTimeoutFor(PeerEgressPolicy policy) {
        if (policy == null || policy.getLimits() == null) {
            return 0;
        }
        return policy.getLimits().getIdleTimeoutSeconds() * 1000L;
    }

    /** Closes a consumer's flows the moment the mesh withdraws its authorization. */
    void revokeConsumer(long consumer, long nowMs) {
        lock.lock();
        try {
            releaseAll(PeerEgressFlowTable.revocationsFor(
                    flows.revokeConsumer(consumer), PeerEgressCodes.PEER_ACL_DENIED), nowMs);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Releases everything. After it returns the runtime forwards nothing, so a caller can rely on it
     * to have stopped traffic rather than merely to have asked it to stop.
     */
    void shutdown(long nowMs) {
        lock.lock();
        try {
            closed = true;
            enabled = false;
            releaseAll(PeerEgressFlowTable.revocationsFor(flows.drain(), PeerEgressCodes.DISABLED), nowMs);
        } finally {
            lock.unlock();
        }
    }

    /**
     * The SPEG1 entry point: one decrypted payload from one consumer.
     *
     * <p>Returns false when the payload is not an egress frame at all, so the mesh dispatch can go
     * on to its other cases. A payload that carries the magic but nothing valid returns true,
     * because it was addressed here and has already been refused with its own code.
     */
    boolean handleFrame(long consumer, byte[] payload, long nowMs) {
        if (!PeerEgressFrame.looksLikeFrame(payload)) {
            return false;
        }
        PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(payload);
        if (!frame.accepted()) {
            refuse(consumer, null, frame.code(), nowMs);
            return true;
        }
        if (frame.type() == PeerEgressFrame.TYPE_IP_PACKET) {
            handleInnerPacket(consumer, frame, nowMs);
        } else if (frame.type() == PeerEgressFrame.TYPE_CONTROL) {
            handleControl(consumer, frame, nowMs);
        }
        return true;
    }

    private void handleInnerPacket(long consumer, PeerEgressFrame.Decoded frame, long nowMs) {
        int protocol = frame.inner().protocol();
        if (protocol == PeerEgressSegment.IPV4_PROTOCOL_TCP) {
            PeerEgressSegment.Segment segment = PeerEgressSegment.parse(frame.body());
            if (segment != null) {
                handleSegment(consumer, segment, nowMs);
                return;
            }
        } else if (protocol == PeerEgressDatagram.IPV4_PROTOCOL_UDP) {
            PeerEgressDatagram.Datagram datagram = PeerEgressDatagram.parse(frame.body());
            if (datagram != null) {
                handleDatagram(consumer, datagram, nowMs);
                return;
            }
        } else {
            // ICMP and anything else this version does not carry. Refusing rather than passing it
            // through is the spec's rule: silently forwarding a protocol we do not account for
            // would leak traffic past the policy.
            refuse(consumer, new PeerEgressFlowTable.Key(
                            protocol, 0, 0, 0, frame.inner().destinationPort()),
                    PeerEgressCodes.PROTOCOL_DENIED, nowMs);
            return;
        }
        refuse(consumer, new PeerEgressFlowTable.Key(protocol, 0, 0, 0, 0),
                PeerEgressCodes.FRAME_TRUNCATED, nowMs);
    }

    private void handleControl(long consumer, PeerEgressFrame.Decoded frame, long nowMs) {
        PeerEgressFrame.Control control = PeerEgressFrame.decodeControl(frame.body());
        if (control == null) {
            return;
        }
        // flow-reject travels egress to consumer. Receiving one means the peer is confused about
        // which end it is, and acting on it would let a consumer close flows by assertion.
        if (!PeerEgressFrame.CONTROL_FLOW_PURGE.equals(control.type())) {
            return;
        }
        lock.lock();
        try {
            // Scoped to the sender: a purge speaks for its own flows, not every other consumer's.
            releaseAll(PeerEgressFlowTable.revocationsFor(
                    flows.purgeDestinations(consumer, control.destinations()), null), nowMs);
        } finally {
            lock.unlock();
        }
    }

    /** Drives one TCP segment from a consumer. */
    private void handleSegment(long consumer, PeerEgressSegment.Segment segment, long nowMs) {
        PeerEgressFlowTable.Key key = new PeerEgressFlowTable.Key(
                PeerEgressSegment.IPV4_PROTOCOL_TCP,
                segment.sourceIp(), segment.sourcePort(),
                segment.destinationIp(), segment.destinationPort());

        lock.lock();
        PeerEgressFlowTable.Flow flow = flows.lookup(key);
        if (flow == null) {
            lock.unlock();
            // Only a SYN opens a flow. A stray segment for something we never opened gets a reset,
            // which is what tells a consumer holding stale state to give up rather than retry.
            if (!segment.has(PeerEgressSegment.FLAG_SYN) || segment.has(PeerEgressSegment.FLAG_ACK)) {
                if (!segment.has(PeerEgressSegment.FLAG_RST)) {
                    emitSegment(consumer, PeerEgressSegment.buildReset(segment));
                }
                return;
            }
            openTcpFlow(consumer, key, segment, nowMs);
            return;
        }

        try {
            if (!(flow.handle instanceof TcpFlow handle)) {
                // The reservation exists but its connect has not returned, so there is no state
                // machine to drive yet. Dropping is correct rather than merely tolerable: the
                // consumer's own retransmission covers it, and answering now would mean answering
                // for a socket that may still fail to open.
                return;
            }
            flow.lastSeenMs = nowMs;
            PeerEgressTcpConnection.Output output = handle.connection().onSegment(segment, nowMs);
            applyTcpOutput(consumer, flow, handle, output);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Authorises, connects and completes the handshake.
     *
     * <p>The connect happens outside the lock: it can take as long as {@link #CONNECT_TIMEOUT_MS},
     * and holding the plane for that would stall every other flow. The reservation is taken first so
     * the quota is charged for the whole attempt, not only after it succeeds; a consumer opening a
     * thousand flows to a black hole would otherwise pass every limit check.
     */
    // Package-private rather than private so a test can drive two calls into it at once. The race
    // it guards -- two frames for one four-tuple both finding no flow -- cannot be produced through
    // the public entry point, because the lock serialises them there.
    void openTcpFlow(long consumer, PeerEgressFlowTable.Key key,
            PeerEgressSegment.Segment syn, long nowMs) {
        lock.lock();
        Reservation reservation = reserve(consumer, key, nowMs);
        if (reservation.code() != null) {
            lock.unlock();
            refuse(consumer, key, reservation.code(), nowMs);
            emitSegment(consumer, PeerEgressSegment.buildReset(syn));
            return;
        }
        if (!reservation.opened()) {
            // A retransmitted SYN, or a second frame that raced this one. The reservation already
            // exists, so dialling again would leave two sockets and two state machines on one entry
            // with the loser leaked. Dropping is right: the consumer retransmits until the flow this
            // call is opening answers.
            lock.unlock();
            return;
        }
        PeerEgressFlowTable.Flow flow = reservation.flow();
        int mtu = pathMtu;
        lock.unlock();

        Socket socket = null;
        IOException failure = null;
        try {
            socket = dialer.dial("tcp", Ipv4Cidr.format(key.remoteIp()), key.remotePort(), CONNECT_TIMEOUT_MS);
        } catch (IOException error) {
            failure = error;
        }

        lock.lock();
        // The flow can have been revoked, purged or drained while the connect was in flight.
        // Closing the socket we just opened is the only correct outcome: the authorization it was
        // opened under no longer exists.
        if (flows.lookup(key) != flow || closed) {
            lock.unlock();
            if (socket != null) {
                socket.close();
            }
            return;
        }
        if (failure != null || socket == null) {
            flows.close(key);
            lock.unlock();
            unreachable(consumer, key, failure);
            emitSegment(consumer, PeerEgressSegment.buildReset(syn));
            return;
        }

        try {
            PeerEgressTcpConnection.Output output = new PeerEgressTcpConnection.Output();
            PeerEgressTcpConnection connection = PeerEgressTcpConnection.accept(
                    syn, newInitialSendSequence(), mtu, flows.idleTimeoutMs(), nowMs, output);
            TcpFlow handle = new TcpFlow(connection, socket);
            flow.handle = handle;
            totalFlows++;
            applyTcpOutput(consumer, flow, handle, output);
            startTcpReader(consumer, flow, handle);
        } finally {
            lock.unlock();
        }
    }

    /** Pumps the real socket into the state machine. Called with the lock held. */
    private void startTcpReader(long consumer, PeerEgressFlowTable.Flow flow, TcpFlow handle) {
        executor.run(() -> {
            byte[] buffer = new byte[TCP_READ_BUFFER];
            while (true) {
                int read;
                try {
                    read = handle.socket().read(buffer);
                } catch (IOException error) {
                    finishTcpReader(consumer, flow, handle, false);
                    return;
                }
                if (read < 0) {
                    // A clean end of stream is a half-close the consumer should see as a FIN.
                    finishTcpReader(consumer, flow, handle, true);
                    return;
                }
                if (read == 0) {
                    continue;
                }
                byte[] data = new byte[read];
                System.arraycopy(buffer, 0, data, 0, read);
                long nowMs = clock.getAsLong();
                lock.lock();
                try {
                    if (flows.lookup(flow.key) != flow) {
                        return;
                    }
                    flow.lastSeenMs = nowMs;
                    flow.bytesFromRemote += read;
                    bytesIn += read;
                    applyTcpOutput(consumer, flow, handle, handle.connection().onAppData(data, nowMs));
                } finally {
                    lock.unlock();
                }
            }
        });
    }

    /**
     * Ends a reader loop. A clean end of stream is a half-close the consumer should see as a FIN;
     * any other error ended the connection abnormally, which is a reset.
     */
    private void finishTcpReader(long consumer, PeerEgressFlowTable.Flow flow, TcpFlow handle,
            boolean endOfStream) {
        long nowMs = clock.getAsLong();
        lock.lock();
        try {
            if (flows.lookup(flow.key) != flow) {
                return;
            }
            PeerEgressTcpConnection.Output output = endOfStream
                    ? handle.connection().onAppClose(nowMs)
                    : handle.connection().abort();
            applyTcpOutput(consumer, flow, handle, output);
        } finally {
            lock.unlock();
        }
    }

    /** Performs everything the state machine asked for. Called with the lock held. */
    private void applyTcpOutput(long consumer, PeerEgressFlowTable.Flow flow, TcpFlow handle,
            PeerEgressTcpConnection.Output output) {
        for (byte[] packet : output.segments) {
            emitSegment(consumer, packet);
        }
        if (output.deliver.length > 0) {
            try {
                handle.socket().write(output.deliver);
            } catch (IOException error) {
                // The socket died under us. Reset rather than leaving the consumer waiting for data
                // that will never arrive.
                for (byte[] packet : handle.connection().abort().segments) {
                    emitSegment(consumer, packet);
                }
                release(flow);
                return;
            }
            flow.bytesToRemote += output.deliver.length;
            bytesOut += output.deliver.length;
        }
        if (output.closeApp) {
            // The consumer finished sending but still expects replies, so only the write side
            // closes. Closing both would discard a response the application is still producing.
            handle.socket().closeWrite();
        }
        if (output.done || output.reset) {
            release(flow);
        }
    }

    /**
     * Drives one UDP datagram from a consumer. UDP has no handshake, so the first datagram of a
     * four-tuple is the authorization point and every later one rides that decision.
     */
    private void handleDatagram(long consumer, PeerEgressDatagram.Datagram datagram, long nowMs) {
        PeerEgressFlowTable.Key key = new PeerEgressFlowTable.Key(
                PeerEgressDatagram.IPV4_PROTOCOL_UDP,
                datagram.sourceIp(), datagram.sourcePort(),
                datagram.destinationIp(), datagram.destinationPort());

        lock.lock();
        PeerEgressFlowTable.Flow flow = flows.lookup(key);
        if (flow == null) {
            Reservation reservation = reserve(consumer, key, nowMs);
            if (reservation.code() != null) {
                lock.unlock();
                refuse(consumer, key, reservation.code(), nowMs);
                return;
            }
            if (!reservation.opened()) {
                // Another datagram for the same four-tuple is already opening this session. Two
                // sockets on one entry would leak the loser and split the session's replies.
                lock.unlock();
                return;
            }
            PeerEgressFlowTable.Flow reserved = reservation.flow();
            lock.unlock();

            Socket socket = null;
            IOException failure = null;
            try {
                socket = dialer.dial("udp", Ipv4Cidr.format(key.remoteIp()), key.remotePort(),
                        CONNECT_TIMEOUT_MS);
            } catch (IOException error) {
                failure = error;
            }

            lock.lock();
            if (flows.lookup(key) != reserved || closed) {
                lock.unlock();
                if (socket != null) {
                    socket.close();
                }
                return;
            }
            if (failure != null || socket == null) {
                flows.close(key);
                lock.unlock();
                unreachable(consumer, key, failure);
                return;
            }
            UdpFlow opened = new UdpFlow(socket);
            reserved.handle = opened;
            totalFlows++;
            startUdpReader(consumer, reserved, opened);
            flow = reserved;
        }

        Socket socket;
        byte[] payload;
        try {
            if (!(flow.handle instanceof UdpFlow handle)) {
                // The session is still connecting. Dropping one datagram is what UDP already
                // promises, and holding it would mean buffering for a socket that may never open.
                return;
            }
            flow.lastSeenMs = nowMs;
            socket = handle.socket();
            payload = datagram.payload();
            flow.bytesToRemote += payload.length;
            bytesOut += payload.length;
        } finally {
            lock.unlock();
        }

        try {
            socket.write(payload);
        } catch (IOException error) {
            lock.lock();
            try {
                releaseKey(key);
            } finally {
                lock.unlock();
            }
        }
    }

    /** Returns the socket's replies to the consumer. Called with the lock held. */
    private void startUdpReader(long consumer, PeerEgressFlowTable.Flow flow, UdpFlow handle) {
        executor.run(() -> {
            byte[] buffer = new byte[UDP_READ_BUFFER];
            while (true) {
                int read;
                try {
                    read = handle.socket().read(buffer);
                } catch (IOException error) {
                    return;
                }
                if (read < 0) {
                    return;
                }
                byte[] payload = new byte[read];
                System.arraycopy(buffer, 0, payload, 0, read);

                lock.lock();
                try {
                    if (flows.lookup(flow.key) != flow) {
                        return;
                    }
                    flow.lastSeenMs = clock.getAsLong();
                    flow.bytesFromRemote += read;
                    bytesIn += read;
                } finally {
                    lock.unlock();
                }

                // Addresses are mirrored from the flow key rather than read off the socket, so a
                // reply can only ever claim the address the consumer asked us to contact.
                emitSegment(consumer, PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(
                        flow.key.remoteIp(), flow.key.consumerIp(),
                        flow.key.remotePort(), flow.key.consumerPort(), payload)));
            }
        });
    }

    /**
     * Advances timers: TCP retransmission and the idle expiry that is the only thing ending a UDP
     * session. Called with no lock held.
     */
    void onTick(long nowMs) {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            for (PeerEgressFlowTable.Flow flow : flowSnapshot()) {
                if (flow.handle instanceof TcpFlow handle) {
                    applyTcpOutput(flow.consumer, flow, handle, handle.connection().onTick(nowMs));
                }
            }
            // An expired session ended the way UDP sessions end. Recording it as a refusal would
            // put normal life cycle events into the counts an operator reads as blocked traffic.
            releaseAll(PeerEgressFlowTable.revocationsFor(flows.expire(nowMs), null), nowMs);
        } finally {
            lock.unlock();
        }
    }

    /** Copies the live flows so a tick can release entries while iterating. */
    private List<PeerEgressFlowTable.Flow> flowSnapshot() {
        List<PeerEgressFlowTable.Flow> snapshot = new ArrayList<>(flows.live());
        PeerEgressFlowTable.sort(snapshot);
        return snapshot;
    }

    /** The outcome of one reservation attempt. A code means refused; otherwise the flow is ours. */
    private record Reservation(PeerEgressFlowTable.Flow flow, String code, boolean opened) {
    }

    /**
     * Runs the judgment layer and, on approval, takes the quota slot. Called with the lock held. The
     * reservation exists before the socket does so that a slow or failing connect still counts
     * against the limits for its whole duration.
     *
     * <p>{@link Reservation#opened()} says whether this call is the one that created the entry. A
     * second frame for the same four-tuple arriving while the first is still connecting finds the
     * reservation already there, and must not dial again.
     */
    private Reservation reserve(long consumer, PeerEgressFlowTable.Key key, long nowMs) {
        if (closed || !enabled) {
            return new Reservation(null, PeerEgressCodes.DISABLED, false);
        }
        boolean peerAllowed = peerAclAllows == null || peerAclAllows.test(consumer);

        PeerEgressRequest request = new PeerEgressRequest();
        request.setConsumerClientId(consumer);
        request.setDestinationIp(Ipv4Cidr.format(key.remoteIp()));
        request.setDestinationPort(key.remotePort());
        request.setProtocol(key.protocolName());
        request.setActiveFlowsForConsumer(flows.countFor(consumer));
        request.setActiveFlowsTotal(flows.size());
        request.setLocalInterfaceCidrs(localInterfaces);

        PeerEgressAuthorization.Decision decision =
                PeerEgressAuthorization.evaluate(request, policy, peerAllowed, context);
        if (!decision.allowed()) {
            return new Reservation(null, decision.code(), false);
        }
        PeerEgressFlowTable.Flow opened = flows.open(key, consumer, nowMs);
        return opened != null
                ? new Reservation(opened, null, true)
                : new Reservation(flows.lookup(key), null, false);
    }

    /**
     * Records a refusal and tells the consumer why. Called with no lock held.
     *
     * <p>The control message is diagnostic only. A refused TCP flow is ended by the reset the caller
     * also sends, because an application waits on its own stack, not on a message it never sees.
     */
    private void refuse(long consumer, PeerEgressFlowTable.Key key, String code, long nowMs) {
        PeerEgressFlowTable.Key subject = key == null
                ? new PeerEgressFlowTable.Key(0, 0, 0, 0, 0)
                : key;
        PeerEgressRejectionLog.Decision decision;
        lock.lock();
        try {
            decision = rejections.record(consumer, code, nowMs);
        } finally {
            lock.unlock();
        }
        if (decision.shouldLog()) {
            if (decision.suppressed() > 0) {
                log.info("[peer-egress] refused consumer={} protocol={} destination={}:{} code={} suppressed={}",
                        consumer, subject.protocolName(), Ipv4Cidr.format(subject.remoteIp()),
                        subject.remotePort(), code, decision.suppressed());
            } else {
                log.info("[peer-egress] refused consumer={} protocol={} destination={}:{} code={}",
                        consumer, subject.protocolName(), Ipv4Cidr.format(subject.remoteIp()),
                        subject.remotePort(), code);
            }
        }
        emitFrame(consumer, PeerEgressFrame.TYPE_CONTROL,
                PeerEgressFrame.encodeControl(PeerEgressFrame.Control.flowReject(
                        subject.protocolName(), Ipv4Cidr.format(subject.consumerIp()),
                        subject.consumerPort(), Ipv4Cidr.format(subject.remoteIp()),
                        subject.remotePort(), code)));
    }

    /**
     * Reports a flow the policy allowed but the network did not deliver. Called with no lock held.
     *
     * <p>Deliberately not a refusal. The spec's codes all describe an authorization or validation
     * outcome, and reporting a refused connection as {@code EGRESS_DEST_DENIED} would send an
     * operator hunting for a policy rule that never fired, while inflating the refusal counts the
     * server aggregates. The consumer learns what happened from the reset its own stack receives,
     * which is what the application waits on anyway.
     */
    private void unreachable(long consumer, PeerEgressFlowTable.Key key, Exception cause) {
        log.info("[peer-egress] connect failed consumer={} protocol={} destination={}:{} err={}",
                consumer, key.protocolName(), Ipv4Cidr.format(key.remoteIp()), key.remotePort(),
                cause == null ? "no socket" : cause.toString());
    }

    /** Closes one flow's socket and drops its table entry. Called with the lock held. */
    private void release(PeerEgressFlowTable.Flow flow) {
        if (flows.lookup(flow.key) == null) {
            return;
        }
        flows.close(flow.key);
        closeHandle(flow.handle);
    }

    private void releaseKey(PeerEgressFlowTable.Key key) {
        PeerEgressFlowTable.Flow flow = flows.close(key);
        if (flow != null) {
            closeHandle(flow.handle);
        }
    }

    /**
     * Closes flows the table already removed. Called with the lock held.
     *
     * <p>The reason travels to the consumer so an operator sees a blocked connection explained
     * rather than merely dropped, and so a client can distinguish a revoked flow from a network
     * failure.
     */
    private void releaseAll(List<PeerEgressFlowTable.Revocation> revoked, long nowMs) {
        for (PeerEgressFlowTable.Revocation entry : revoked) {
            PeerEgressFlowTable.Flow flow = entry.flow();
            if (flow.handle instanceof TcpFlow handle) {
                // The reset is what the application actually reacts to. Without it a consumer sits
                // waiting on a connection this node has already stopped serving.
                for (byte[] packet : handle.connection().abort().segments) {
                    emitSegment(flow.consumer, packet);
                }
            }
            closeHandle(flow.handle);
            if (entry.code() == null) {
                continue;
            }
            rejections.record(flow.consumer, entry.code(), nowMs);
            emitFrame(flow.consumer, PeerEgressFrame.TYPE_CONTROL,
                    PeerEgressFrame.encodeControl(PeerEgressFrame.Control.flowReject(
                            flow.key.protocolName(), Ipv4Cidr.format(flow.key.consumerIp()),
                            flow.key.consumerPort(), Ipv4Cidr.format(flow.key.remoteIp()),
                            flow.key.remotePort(), entry.code())));
        }
    }

    private static void closeHandle(Object handle) {
        if (handle instanceof TcpFlow tcp) {
            tcp.socket().close();
        } else if (handle instanceof UdpFlow udp) {
            udp.socket().close();
        }
    }

    private void emitSegment(long consumer, byte[] packet) {
        emitFrame(consumer, PeerEgressFrame.TYPE_IP_PACKET, packet);
    }

    /**
     * Wraps a body and hands it to the sender. hop stays clear: this node is acting as an egress,
     * not forwarding as a consumer of another one.
     */
    private void emitFrame(long consumer, int type, byte[] body) {
        if (sender != null) {
            sender.send(consumer, PeerEgressFrame.encode(type, false, body));
        }
    }

    /**
     * Records the budget a returning segment has to fit. Only ever set towards what the path
     * actually measured; a value below the IPv4 minimum is ignored rather than applied, since a bad
     * measurement should not be able to shrink every flow's segments to nothing.
     */
    void setPathMtu(int mtu) {
        if (mtu < PeerEgressSegment.IPV4_MIN_HEADER_BYTES
                + PeerEgressSegment.TCP_MIN_HEADER_BYTES + PeerEgressSegment.DEFAULT_MSS) {
            return;
        }
        lock.lock();
        try {
            pathMtu = mtu;
        } finally {
            lock.unlock();
        }
    }

    void setLocalInterfaceCidrs(List<String> networks) {
        lock.lock();
        try {
            localInterfaces = networks == null ? List.of() : List.copyOf(networks);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Applies the spec's monotonic guard: a snapshot at or below the last accepted one is ignored,
     * so a reordered or replayed push cannot walk the policy backwards. A revision of zero is
     * accepted, since a server that numbers nothing must still be able to configure the node.
     */
    boolean acceptRevision(long candidate) {
        lock.lock();
        try {
            if (candidate != 0 && candidate <= revision) {
                return false;
            }
            revision = candidate;
            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Picks an initial send sequence number.
     *
     * <p>Random rather than counted: a predictable value lets anyone who can guess the four-tuple
     * inject segments a flow will accept.
     */
    private int newInitialSendSequence() {
        return random.nextInt();
    }
}
