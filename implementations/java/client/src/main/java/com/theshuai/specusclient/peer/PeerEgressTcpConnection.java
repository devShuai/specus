package com.theshuai.specusclient.peer;

import com.theshuai.specusclient.peer.PeerEgressSegment.Segment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * User-space TCP termination for the egress side.
 *
 * <p>Owns no sockets and reads no clock. Effects come back in {@link Output}, or through an
 * optional nonblocking queue-admission callback that must not do network I/O or take a mesh lock.
 * Rejection leaves data unsent. The conformance suite can drive loss, reordering and
 * timers deterministically without a network. And the same scenarios run against Go and .NET, where
 * the I/O and scheduling primitives are different but the protocol decisions must not be.
 *
 * <p>Held to {@code peer-egress-tcp-v1.json}, the shared fixture all three runtimes replay.
 */
final class PeerEgressTcpConnection {

    enum State {
        SYN_RECEIVED,
        ESTABLISHED,
        /** The application (the real socket) closed first, so we sent FIN and await its acknowledgement. */
        FIN_WAIT_1,
        FIN_WAIT_2,
        /** The consumer closed first; we owe a FIN once the real socket drains. */
        CLOSE_WAIT,
        CLOSING,
        LAST_ACK,
        TIME_WAIT,
        CLOSED
    }

    /**
     * Our advertised receive window, not the downstream send credit. Downstream sends obey the
     * peer window and a conservative four-MSS flight limit, not adaptive congestion control.
     *
     * <p>65535 and not 64 KiB: the header field is sixteen bits and there is no window scaling in
     * this version, so a 65536 would go on the wire as a zero window and tell every consumer to
     * stop sending.
     */
    static final int RECEIVE_WINDOW = 65535;
    static final int SEND_BUFFER = 65536;

    static final long INITIAL_RTO_MS = 1000;
    static final long MIN_RTO_MS = 200;
    static final long MAX_RTO_MS = 60_000;

    /** How many times one segment is resent before the flow is abandoned. */
    static final int MAX_RETRANSMITS = 6;

    /**
     * Deliberately short of the classic 2*MSL. Nothing else on this host can bind the four-tuple,
     * since it exists only inside this stack, so the window only has to outlive stragglers on the
     * mesh path.
     */
    static final long TIME_WAIT_MS = 10_000;

    /** Bounds out-of-order segments held per flow, so a peer that sends a hole cannot flood us. */
    static final int MAX_REASSEMBLY = 32;

    /**
     * Keepalive finds out whether a silent consumer is still there sooner than the idle timeout
     * would. It deliberately does not extend the idle budget: that budget is a resource limit
     * rather than a liveness question.
     */
    static final long KEEPALIVE_IDLE_MS = 15_000;
    static final long KEEPALIVE_INTERVAL_MS = 5_000;
    static final int KEEPALIVE_PROBES = 3;

    /** Everything the state machine wants the caller to do. It never acts itself. */
    static final class Output {
        final List<byte[]> segments = new ArrayList<>();
        /** Payload to write to the real socket, in order. */
        byte[] deliver = new byte[0];
        /** The consumer finished sending, so the real socket should be half-closed for writing. */
        boolean closeApp;
        /** The flow is finished and its resources can be released. */
        boolean done;
        /** The flow ended abnormally; drop the socket rather than closing it gracefully. */
        boolean reset;

        void send(byte[] packet) {
            segments.add(packet);
        }

        void appendDeliver(byte[] data) {
            if (data.length == 0) {
                return;
            }
            byte[] merged = Arrays.copyOf(deliver, deliver.length + data.length);
            System.arraycopy(data, 0, merged, deliver.length, data.length);
            deliver = merged;
        }
    }

    private static final class RetransmitEntry {
        int seq;
        int flags;
        byte[] payload;
        long sentAtMs;
        int attempts;
        /**
         * Marks a segment that was resent, so its round-trip sample is discarded. That is Karn's
         * algorithm: an ambiguous sample would poison the estimator whenever loss happens.
         */
        boolean retransmitted;
    }

    private static final class OutOfOrder {
        int seq;
        byte[] payload;
        boolean fin;
    }

    private final int localIp;
    private final int remoteIp;
    private final int localPort;
    private final int remotePort;

    private State state;

    private final int iss;
    private int sndUna;
    private int sndNxt;
    private int sndWnd;
    private int sndWl1;
    private int sndWl2;
    private byte[] pending = new byte[0];
    // Nonblocking transport admission; null keeps the deterministic output-only model.
    java.util.function.Predicate<byte[]> tryTransmit;
    boolean sendBlocked;
    private long persistAtMs = -1;

    private final int irs;
    private int rcvNxt;
    private int rcvWnd;

    private int sndMss;

    private final List<RetransmitEntry> retransmit = new ArrayList<>();
    private long rtoMs = INITIAL_RTO_MS;
    private long srttMs;
    private long rttvarMs;

    private final List<OutOfOrder> reassembly = new ArrayList<>();

    private int finSeq;
    private boolean finSent;
    private boolean finReceived;
    private boolean appClosed;

    private long lastActivityMs;
    private long closedAtMs;
    private final long idleTimeoutMs;

    private int keepaliveProbes;
    private long lastProbeMs;
    private boolean probed;

    private PeerEgressTcpConnection(Segment syn, int iss, long idleTimeoutMs, long nowMs) {
        this.localIp = syn.destinationIp();
        this.remoteIp = syn.sourceIp();
        this.localPort = syn.destinationPort();
        this.remotePort = syn.sourcePort();
        this.state = State.SYN_RECEIVED;
        this.iss = iss;
        this.sndUna = iss;
        this.sndNxt = iss;
        this.sndWnd = syn.window();
        this.sndWl1 = syn.seq();
        this.irs = syn.seq();
        this.rcvNxt = syn.seq() + 1;
        this.rcvWnd = RECEIVE_WINDOW;
        this.lastActivityMs = nowMs;
        this.idleTimeoutMs = idleTimeoutMs;
    }

    /**
     * Opens a flow from the consumer's SYN and produces the SYN-ACK.
     *
     * <p>The initial send sequence is supplied rather than generated here so tests are
     * deterministic; production passes a random value, which is what keeps an off-path attacker
     * from guessing the sequence space.
     */
    static PeerEgressTcpConnection accept(
            Segment syn, int iss, int pathMtu, long idleTimeoutMs, long nowMs, Output output) {
        PeerEgressTcpConnection connection =
                new PeerEgressTcpConnection(syn, iss, idleTimeoutMs, nowMs);
        int advertised = connection.advertisedMss(pathMtu);
        connection.sndMss = syn.mss() > 0 ? Math.min(syn.mss(), advertised) : advertised;
        connection.emit(output, PeerEgressSegment.FLAG_SYN | PeerEgressSegment.FLAG_ACK,
                new byte[0], nowMs, advertised);
        return connection;
    }

    State state() {
        return state;
    }

    boolean done() {
        return state == State.CLOSED;
    }

    int sendMss() {
        return sndMss;
    }

    private int advertisedMss(int pathMtu) {
        int mss = pathMtu - PeerEgressSegment.IPV4_MIN_HEADER_BYTES
                - PeerEgressSegment.TCP_MIN_HEADER_BYTES;
        return Math.max(mss, PeerEgressSegment.DEFAULT_MSS);
    }

    /** Renders one segment, queues it for retransmission when it occupies sequence space, and advances SND.NXT. */
    private boolean transmit(Output output, byte[] packet) {
        if (tryTransmit != null) {
            boolean accepted = tryTransmit.test(packet);
            sendBlocked = !accepted;
            return accepted;
        }
        output.send(packet);
        return true;
    }

    private boolean emit(Output output, int flags, byte[] payload, long nowMs, int mss) {
        Segment segment = new Segment(
                localIp, remoteIp, localPort, remotePort,
                sndNxt, rcvNxt, flags,
                PeerEgressSegment.advertisedWindow(rcvWnd), mss, payload);
        if (!transmit(output, PeerEgressSegment.build(segment))) { return false; }

        int length = segment.segmentLength();
        if (length == 0) {
            return true;
        }
        RetransmitEntry entry = new RetransmitEntry();
        entry.seq = sndNxt;
        entry.flags = flags;
        entry.payload = payload;
        entry.sentAtMs = nowMs;
        retransmit.add(entry);
        if (segment.has(PeerEgressSegment.FLAG_FIN)) {
            finSeq = sndNxt + length - 1;
            finSent = true;
        }
        sndNxt += length;
        return true;
    }

    private void ack(Output output, long nowMs) {
        emit(output, PeerEgressSegment.FLAG_ACK, new byte[0], nowMs, 0);
    }

    /**
     * Sends a reset and closes the flow.
     *
     * <p>The acknowledgement field is zero, not RCV.NXT. RFC 793 sends a reset that carries no ACK
     * flag as {@code <SEQ=SND.NXT><CTL=RST>}, and a field a receiver is told to ignore should not
     * carry a value that looks meaningful.
     */
    private void reset(Output output) {
        output.send(PeerEgressSegment.build(new Segment(
                localIp, remoteIp, localPort, remotePort,
                sndNxt, 0, PeerEgressSegment.FLAG_RST, 0, 0, new byte[0])));
        state = State.CLOSED;
        retransmit.clear();
        pending = new byte[0];
        reassembly.clear();
        output.done = true;
        output.reset = true;
    }

    /** Drives one segment arriving from the consumer. */
    Output onSegment(Segment segment, long nowMs) {
        Output output = new Output();
        if (state == State.CLOSED) {
            return output;
        }

        // Any segment proves the consumer is still there, so the probe run restarts. The idle clock
        // is different: it measures data, not liveness. Letting a keepalive exchange refresh it
        // would mean two stacks could hold a socket and a quota slot open indefinitely by pinging
        // each other, which is exactly the resource the timeout exists to bound.
        keepaliveProbes = 0;
        if (segment.segmentLength() > 0) {
            lastActivityMs = nowMs;
        }

        if (segment.has(PeerEgressSegment.FLAG_RST)) {
            // An in-window reset ends the flow. Out-of-window resets are ignored, which is what
            // stops a blind off-path attacker from tearing down flows by guessing.
            if (PeerEgressSegment.seqInWindow(segment.seq(), rcvNxt, rcvWnd)
                    || segment.seq() == rcvNxt) {
                state = State.CLOSED;
                retransmit.clear();
                pending = new byte[0];
                reassembly.clear();
                output.done = true;
                output.reset = true;
            }
            return output;
        }

        if (segment.has(PeerEgressSegment.FLAG_SYN) && state != State.SYN_RECEIVED) {
            // A SYN inside an established flow is either a stale duplicate or an attack; RFC 793
            // says answer with a reset rather than silently re-handshaking.
            reset(output);
            return output;
        }

        if (segment.has(PeerEgressSegment.FLAG_ACK)) {
            processAck(segment, nowMs, output);
            if (state == State.CLOSED) {
                output.done = true;
                return output;
            }
        }

        if (state == State.SYN_RECEIVED) {
            if (!segment.has(PeerEgressSegment.FLAG_ACK) || sndUna != iss + 1) {
                // A duplicate SYN: resend the SYN-ACK rather than opening a second flow.
                return output;
            }
            state = State.ESTABLISHED;
        }
        flushSend(output, nowMs);

        // RFC 1122: a keepalive probe re-sends one byte of already acknowledged sequence space to
        // force an acknowledgement. Without answering it, a healthy flow looks dead to the consumer
        // and gets torn down from the far end. A normal bare ACK carries the sequence we already
        // expect, so only one below it is a probe.
        if (segment.payload().length == 0
                && !segment.has(PeerEgressSegment.FLAG_FIN)
                && !segment.has(PeerEgressSegment.FLAG_SYN)
                && PeerEgressSegment.seqLess(segment.seq(), rcvNxt)) {
            ack(output, nowMs);
            return output;
        }

        acceptData(segment, nowMs, output);
        updateStateAfterFin(output, nowMs);
        return output;
    }

    /** Advances the send window and retires acknowledged retransmission entries. */
    private void processAck(Segment segment, long nowMs, Output output) {
        int ack = segment.ack();
        if (PeerEgressSegment.seqLess(ack, sndUna) || PeerEgressSegment.seqLess(sndNxt, ack)) {
            // Acknowledges something we never sent. Ignored rather than answered with a reset: a
            // delayed duplicate must not be able to kill a healthy connection.
            return;
        }
        sndUna = ack;
        if (PeerEgressSegment.seqLess(sndWl1, segment.seq())
                || (sndWl1 == segment.seq() && PeerEgressSegment.seqLessEqual(sndWl2, ack))) {
            sndWnd = segment.window();
            sndWl1 = segment.seq();
            sndWl2 = ack;
            if (sndWnd > 0) { persistAtMs = -1; }
        }

        List<RetransmitEntry> kept = new ArrayList<>(retransmit.size());
        for (RetransmitEntry entry : retransmit) {
            int end = entry.seq + entryLength(entry);
            if (PeerEgressSegment.seqLessEqual(end, ack)) {
                if (!entry.retransmitted) {
                    updateRto(nowMs - entry.sentAtMs);
                }
                continue;
            }
            if (PeerEgressSegment.seqLess(entry.seq, sndUna) && entry.payload.length > 0) {
                int skip = Math.min(sndUna - entry.seq, entry.payload.length);
                entry.payload = Arrays.copyOfRange(entry.payload, skip, entry.payload.length);
                entry.seq += skip;
            }
            kept.add(entry);
        }
        retransmit.clear();
        retransmit.addAll(kept);

        if (finSent && PeerEgressSegment.seqLessEqual(finSeq + 1, ack)) {
            switch (state) {
                case FIN_WAIT_1 -> state = State.FIN_WAIT_2;
                case CLOSING -> enterTimeWait(nowMs);
                case LAST_ACK -> {
                    state = State.CLOSED;
                    output.done = true;
                }
                default -> {
                }
            }
        }
    }

    private static int entryLength(RetransmitEntry entry) {
        int length = entry.payload.length;
        if ((entry.flags & PeerEgressSegment.FLAG_SYN) != 0) {
            length++;
        }
        if ((entry.flags & PeerEgressSegment.FLAG_FIN) != 0) {
            length++;
        }
        return length;
    }

    /** Jacobson/Karels, with the floor and ceiling the constants name. */
    private void updateRto(long sampleMs) {
        if (sampleMs <= 0) {
            return;
        }
        if (srttMs == 0) {
            srttMs = sampleMs;
            rttvarMs = sampleMs / 2;
        } else {
            long delta = Math.abs(srttMs - sampleMs);
            rttvarMs = (3 * rttvarMs + delta) / 4;
            srttMs = (7 * srttMs + sampleMs) / 8;
        }
        long candidate = srttMs + 4 * rttvarMs;
        rtoMs = Math.min(Math.max(candidate, MIN_RTO_MS), MAX_RTO_MS);
    }

    /** Takes in-order payload, buffers out-of-order payload, and acknowledges. */
    private void acceptData(Segment segment, long nowMs, Output output) {
        byte[] payload = segment.payload();
        if (payload.length == 0 && !segment.has(PeerEgressSegment.FLAG_FIN)) {
            return;
        }
        if (finReceived) {
            // Data after the peer's FIN is a protocol violation. Reset instead of quietly dropping,
            // so the far end learns its stack is out of step.
            if (payload.length > 0) {
                reset(output);
            }
            return;
        }

        int seq = segment.seq();
        if (PeerEgressSegment.seqLess(seq, rcvNxt)) {
            // Wholly or partly retransmitted. Trim what we already have; if nothing new remains
            // this is a duplicate and only needs an ACK to re-synchronise the peer.
            int skip = rcvNxt - seq;
            if (skip >= payload.length) {
                if (segment.has(PeerEgressSegment.FLAG_FIN)
                        && seq + segment.segmentLength() - 1 == rcvNxt) {
                    finReceived = true;
                    rcvNxt++;
                    output.closeApp = true;
                }
                ack(output, nowMs);
                return;
            }
            payload = Arrays.copyOfRange(payload, skip, payload.length);
            seq = rcvNxt;
        }

        if (!PeerEgressSegment.seqInWindow(seq, rcvNxt, rcvWnd)) {
            // Outside the advertised window. Acknowledge so the peer re-syncs, but take nothing.
            ack(output, nowMs);
            return;
        }

        if (seq != rcvNxt) {
            bufferOutOfOrder(seq, payload, segment.has(PeerEgressSegment.FLAG_FIN));
            ack(output, nowMs);
            return;
        }

        output.appendDeliver(payload);
        rcvNxt += payload.length;
        if (segment.has(PeerEgressSegment.FLAG_FIN)) {
            finReceived = true;
            rcvNxt++;
            output.closeApp = true;
        }
        drainReassembly(output);
        ack(output, nowMs);
    }

    private void bufferOutOfOrder(int seq, byte[] payload, boolean fin) {
        if (reassembly.size() >= MAX_REASSEMBLY) {
            // Dropping is safe: the peer will retransmit. Growing without bound is not.
            return;
        }
        for (OutOfOrder held : reassembly) {
            if (held.seq == seq) {
                return;
            }
        }
        OutOfOrder entry = new OutOfOrder();
        entry.seq = seq;
        entry.payload = payload;
        entry.fin = fin;
        reassembly.add(entry);
    }

    private void drainReassembly(Output output) {
        boolean progressed = true;
        while (progressed) {
            progressed = false;
            for (int index = 0; index < reassembly.size(); index++) {
                OutOfOrder held = reassembly.get(index);
                if (held.seq != rcvNxt) {
                    continue;
                }
                output.appendDeliver(held.payload);
                rcvNxt += held.payload.length;
                if (held.fin) {
                    finReceived = true;
                    rcvNxt++;
                    output.closeApp = true;
                }
                reassembly.remove(index);
                progressed = true;
                break;
            }
        }
    }

    private void updateStateAfterFin(Output output, long nowMs) {
        if (!finReceived) {
            return;
        }
        switch (state) {
            case ESTABLISHED -> state = State.CLOSE_WAIT;
            case FIN_WAIT_1 -> state = State.CLOSING;
            case FIN_WAIT_2 -> enterTimeWait(nowMs);
            default -> {
            }
        }
    }

    private void enterTimeWait(long nowMs) {
        state = State.TIME_WAIT;
        closedAtMs = nowMs;
        retransmit.clear();
        reassembly.clear();
    }

    /** Data read from the real socket, on its way to the consumer. */
    Output onAppData(byte[] data, long nowMs) {
        Output output = new Output();
        if (appClosed || (state != State.SYN_RECEIVED && state != State.ESTABLISHED && state != State.CLOSE_WAIT)) {
            return output;
        }
        if (data.length > appReadCredit()) { reset(output); return output; }
        lastActivityMs = nowMs;
        int previous = pending.length;
        pending = Arrays.copyOf(pending, previous + data.length);
        System.arraycopy(data, 0, pending, previous, data.length);
        flushSend(output, nowMs);
        return output;
    }

    /** Both unsent and unacknowledged bytes consume credit; socket readers wait for ACKs. */
    int appReadCredit() {
        if (appClosed || (state != State.SYN_RECEIVED && state != State.ESTABLISHED && state != State.CLOSE_WAIT)) { return 0; }
        return Math.max(0, SEND_BUFFER - pending.length - (sndNxt - sndUna));
    }

    private int sendCredit() { return Math.max(0, Math.min(sndWnd, 4 * sndMss) - (sndNxt - sndUna)); }

    private void flushSend(Output output, long nowMs) {
        if (state != State.ESTABLISHED && state != State.CLOSE_WAIT) { return; }
        while (pending.length > 0 && sendCredit() > 0) {
            int n = Math.min(pending.length, Math.min(sndMss, sendCredit()));
            if (!emit(output, PeerEgressSegment.FLAG_ACK | PeerEgressSegment.FLAG_PSH,
                    Arrays.copyOf(pending, n), nowMs, 0)) { return; }
            pending = Arrays.copyOfRange(pending, n, pending.length);
        }
        if (appClosed && pending.length == 0 && sendCredit() > 0 && !finSent) {
            if (!emit(output, PeerEgressSegment.FLAG_ACK | PeerEgressSegment.FLAG_FIN,
                    new byte[0], nowMs, 0)) { return; }
            state = state == State.CLOSE_WAIT ? State.LAST_ACK : State.FIN_WAIT_1;
        }
    }

    /** The real socket reached EOF. */
    Output onAppClose(long nowMs) {
        Output output = new Output();
        if (appClosed || state == State.CLOSED) {
            return output;
        }
        appClosed = true;
        lastActivityMs = nowMs;
        flushSend(output, nowMs);
        return output;
    }

    /** Tears the flow down deliberately, which is what a revocation or a quota breach uses. */
    Output abort() {
        Output output = new Output();
        if (state == State.CLOSED) {
            return output;
        }
        reset(output);
        return output;
    }

    /** Drives retransmission, the TIME_WAIT expiry, the idle timeout and keepalive. */
    Output onTick(long nowMs) {
        Output output = new Output();
        if (state == State.CLOSED) {
            return output;
        }
        if (state == State.TIME_WAIT) {
            if (nowMs - closedAtMs >= TIME_WAIT_MS) {
                state = State.CLOSED;
                output.done = true;
            }
            return output;
        }
        if (idleTimeoutMs > 0 && nowMs - lastActivityMs >= idleTimeoutMs) {
            // An idle flow holds a socket and a quota slot on the egress; reclaim it rather than
            // letting a forgotten consumer pin resources. Checked before the keepalive so a probe
            // cannot hold a flow past the limit the policy set.
            reset(output);
            return output;
        }
        flushSend(output, nowMs);
        if (sndWnd == 0 && state != State.SYN_RECEIVED
                && (pending.length > 0 || !retransmit.isEmpty() || appClosed)) {
            if (persistAtMs < 0) { persistAtMs = nowMs; return output; }
            if (nowMs - persistAtMs < rtoMs) { return output; }
            persistAtMs = nowMs;
            if (retransmit.isEmpty() && pending.length > 0) {
                if (emit(output, PeerEgressSegment.FLAG_ACK | PeerEgressSegment.FLAG_PSH,
                        Arrays.copyOf(pending, 1), nowMs, 0)) {
                    pending = Arrays.copyOfRange(pending, 1, pending.length);
                }
            } else {
                int seq = sndNxt - 1;
                byte[] payload = new byte[0];
                if (!retransmit.isEmpty() && retransmit.get(0).payload.length > 0) {
                    RetransmitEntry entry = retransmit.get(0);
                    entry.retransmitted = true;
                    seq = entry.seq;
                    payload = Arrays.copyOf(entry.payload, 1);
                }
                transmit(output, PeerEgressSegment.build(new Segment(localIp, remoteIp, localPort, remotePort,
                        seq, rcvNxt, PeerEgressSegment.FLAG_ACK, PeerEgressSegment.advertisedWindow(rcvWnd), 0, payload)));
            }
            return output;
        }
        if (retransmit.isEmpty() && pending.length == 0 && keepalive(nowMs, output)) {
            return output;
        }

        for (int index = 0; index < Math.min(1, retransmit.size()); index++) {
            RetransmitEntry entry = retransmit.get(index);
            if (nowMs - entry.sentAtMs < rtoMs) {
                continue;
            }
            if (entry.attempts >= MAX_RETRANSMITS) {
                reset(output);
                return output;
            }
            if (!transmit(output, PeerEgressSegment.build(new Segment(
                    localIp, remoteIp, localPort, remotePort,
                    entry.seq, rcvNxt, entry.flags,
                    PeerEgressSegment.advertisedWindow(rcvWnd), 0, state == State.SYN_RECEIVED ? entry.payload
                            : Arrays.copyOf(entry.payload, Math.min(entry.payload.length, sndWnd)))))) {
                return output;
            }
            entry.attempts++;
            entry.retransmitted = true;
            entry.sentAtMs = nowMs;
            // Back off the connection's RTO once per oldest-segment timeout, capped.
            rtoMs = Math.min(rtoMs * 2, MAX_RTO_MS);
        }
        return output;
    }

    /**
     * Probes a silent flow and reports whether the flow ended because the consumer never answered.
     *
     * <p>Established flows only: in any closing state the peer already told us where it stands, and
     * the retransmission timer covers whatever is still outstanding.
     *
     * <p>The probe carries the last byte of already acknowledged sequence space and no payload,
     * which is what RFC 1122 says forces an acknowledgement. It is built directly rather than
     * through emit because it occupies no new sequence space and must not enter the retransmission
     * queue.
     */
    private boolean keepalive(long nowMs, Output output) {
        if (state != State.ESTABLISHED || nowMs - lastActivityMs < KEEPALIVE_IDLE_MS) {
            return false;
        }
        if (keepaliveProbes >= KEEPALIVE_PROBES) {
            reset(output);
            return true;
        }
        if (probed && nowMs - lastProbeMs < KEEPALIVE_INTERVAL_MS) {
            return false;
        }
        keepaliveProbes++;
        probed = true;
        lastProbeMs = nowMs;
        output.send(PeerEgressSegment.build(new Segment(
                localIp, remoteIp, localPort, remotePort,
                sndNxt - 1, rcvNxt, PeerEgressSegment.FLAG_ACK,
                PeerEgressSegment.advertisedWindow(rcvWnd), 0, new byte[0])));
        return false;
    }
}
