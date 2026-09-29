package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressRule;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import lombok.extern.slf4j.Slf4j;

/**
 * The consumer's DNS responder (protocol/spec/peer-egress-dns.md, section three).
 *
 * <p>It opens no socket. The pool route sends the listen address -- the first address of the pool
 * -- into the TUN, and the consumer hands this class the UDP and TCP packets for port 53 there
 * before it steers anything; answers are written back into the TUN. So it takes no system port 53
 * and needs no address on the TUN, and whatever the system sends its queries by -- systemd-resolved
 * per link, Windows NRPT, a macOS network service -- reaches it by route.
 *
 * <p>A query is decided by {@link PeerEgressDnsMessage}: answered here, forwarded to the upstreams
 * the caller names, or dropped. Over TCP, which an application falls back to after a truncated
 * answer, this is the smallest endpoint RFC 7766 needs: a handshake with an MSS no larger than the
 * peer's or 1360, in-order data only, two-byte length framing, answers in the order the queries
 * arrived (a forwarded one holding back those behind it), one-second retransmission three times and
 * then a reset, FIN once everything owed is written, a FIN of its own after ten idle seconds, and at
 * most 64 connections.
 *
 * <p>Thread-safe on its own lock: the consumer calls in from the TUN read path under its monitor,
 * forwarded replies arrive on their own threads, and a clock drives retransmission and idle close.
 * Nothing here takes the consumer's monitor, so that order cannot invert.
 */
@Slf4j
final class PeerEgressDnsResponder implements AutoCloseable {

    static final int PORT = 53;
    /** The largest segment sent, and what the handshake advertises. */
    static final int TCP_MSS = 1360;
    static final int MAX_TCP_CONNECTIONS = 64;
    static final long RETRANSMIT_MS = 1_000L;
    static final int MAX_RETRANSMITS = 3;
    /** A connection with no new and no unanswered query for this long is closed from this side. */
    static final long IDLE_MS = 10_000L;
    /**
     * Forwards in flight at once. Each holds a socket for up to two seconds per upstream; a local
     * application in a loop should not be able to turn that into thousands of sockets. Beyond it a
     * query is answered SERVFAIL, as a failed forward would be.
     */
    static final int MAX_FORWARDS = 256;
    static final long TICK_MS = 200L;
    private static final int WINDOW = 65_535;

    /** Takes one query to the upstreams in order and returns the first reply, or null. Blocking. */
    interface Forwarder {
        byte[] forward(byte[] query, boolean tcp, List<InetSocketAddress> upstreams);
    }

    /** What the status shows: where it listens, whom it forwards to, and what it did. */
    record Stats(String listen, List<String> upstreams, long answered, long forwarded, long failed) {
    }

    /**
     * What the responder did since the process started: answers built here, replies relayed from
     * an upstream, and SERVFAIL for a forward that got no reply, for one past the in-flight limit,
     * or for a full pool. Dropped queries are not counted. Kept outside any one responder, because
     * the status reports them whenever takeover is asked for, running or not, and a responder is
     * replaced when its pool is.
     */
    static final class Counters {
        private final AtomicLong answered = new AtomicLong();
        private final AtomicLong forwarded = new AtomicLong();
        private final AtomicLong failed = new AtomicLong();

        long answered() {
            return answered.get();
        }

        long forwarded() {
            return forwarded.get();
        }

        long failed() {
            return failed.get();
        }
    }

    /** Hands a forwarded reply, or the SERVFAIL for none, to whoever asked; false if they are gone. */
    private interface Delivery {
        boolean deliver(byte[] reply);
    }

    /** One answer owed on a TCP connection, in arrival order; null until a forward comes back. */
    private static final class Slot {
        byte[] answer;

        Slot(byte[] answer) {
            this.answer = answer;
        }
    }

    /** A growable byte run, consumed from the front. */
    private static final class Bytes {
        byte[] data = new byte[256];
        int length;

        void append(byte[] source, int offset, int count) {
            if (length + count > data.length) {
                data = Arrays.copyOf(data, Math.max(data.length * 2, length + count));
            }
            System.arraycopy(source, offset, data, length, count);
            length += count;
        }

        void drop(int count) {
            System.arraycopy(data, count, data, 0, length - count);
            length -= count;
        }
    }

    /** One TCP connection to the listen address. */
    private static final class Connection {
        final int ip;
        final int port;
        final int iss;
        final int irs;
        final int mss;
        boolean established;
        /** The sequence number of the first byte of {@link #out}: everything before is acknowledged. */
        int sndBase;
        /** Answers framed and not yet acknowledged; the first {@link #sent} bytes have gone out. */
        final Bytes out = new Bytes();
        int sent;
        int rcvNxt;
        /** Received in order and not yet a whole query. */
        final Bytes in = new Bytes();
        final ArrayDeque<Slot> slots = new ArrayDeque<>();
        boolean peerFin;
        boolean closeWanted;
        boolean finSent;
        boolean finAcked;
        long finSentAtMs;
        long lastQueryMs;
        long retransmitAtMs = Long.MAX_VALUE;
        int retries;

        Connection(int ip, int port, int iss, int irs, int mss, long nowMs) {
            this.ip = ip;
            this.port = port;
            this.iss = iss;
            this.irs = irs;
            this.mss = mss;
            this.sndBase = iss + 1;
            this.rcvNxt = irs + 1;
            this.lastQueryMs = nowMs;
        }

        /** The next sequence number this side would use. */
        int sndNxt() {
            return sndBase + sent + (finSent ? 1 : 0);
        }

        boolean outstanding() {
            return sent > 0 || (finSent && !finAcked);
        }
    }

    private final PeerEgressFakeIpPool pool;
    private final Forwarder forwarder;
    private final Executor executor;
    private final PeerEgressConsumer.TunWriter tun;
    private final LongSupplier clock;
    private final int listen;
    private final SecureRandom random = new SecureRandom();

    private List<String> upstreamTexts = List.of();
    private List<InetSocketAddress> upstreams = List.of();
    private String upstreamsLogged = "";
    private boolean noUpstreamLogged;
    private boolean overloadLogged;
    private final Counters counters;
    private int forwarding;
    /** Packets written, so a segment can tell whether something since carried its ACK. */
    private long writes;
    private boolean closed;
    private Thread ticker;
    private final Map<Long, Connection> connections = new LinkedHashMap<>();

    PeerEgressDnsResponder(PeerEgressFakeIpPool pool, Forwarder forwarder, Executor executor,
            PeerEgressConsumer.TunWriter tun, LongSupplier clock) {
        this(pool, forwarder, executor, tun, clock, new Counters());
    }

    PeerEgressDnsResponder(PeerEgressFakeIpPool pool, Forwarder forwarder, Executor executor,
            PeerEgressConsumer.TunWriter tun, LongSupplier clock, Counters counters) {
        this.counters = counters;
        this.pool = pool;
        this.forwarder = forwarder;
        this.executor = executor;
        this.tun = tun;
        this.clock = clock;
        this.listen = pool.listenAddress();
    }

    /** The responder for a pool, forwarding with real sockets and ticking on its own thread. */
    static PeerEgressDnsResponder start(PeerEgressFakeIpPool pool, Forwarder forwarder,
            PeerEgressConsumer.TunWriter tun, Counters counters) {
        PeerEgressDnsResponder responder = new PeerEgressDnsResponder(pool, forwarder,
                task -> Thread.ofVirtual().name("peer-egress-dns-forward").start(task), tun,
                System::currentTimeMillis, counters);
        responder.ticker = Thread.ofVirtual().name("peer-egress-dns-tick").start(() -> {
            while (!responder.isClosed()) {
                try {
                    Thread.sleep(TICK_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
                responder.onTick(System.currentTimeMillis());
            }
        });
        return responder;
    }

    /** The pool this answers from. */
    PeerEgressFakeIpPool pool() {
        return pool;
    }

    int listenAddress() {
        return listen;
    }

    /**
     * The upstreams forwarded queries go to, in order. Step five supplies the ones it recorded; an
     * entry that is not a literal address is left out and said once. None at all means every
     * forwarded query is answered SERVFAIL.
     */
    synchronized void setUpstreams(List<String> texts) {
        List<String> kept = new ArrayList<>();
        List<InetSocketAddress> parsed = new ArrayList<>();
        List<String> refused = new ArrayList<>();
        for (String text : texts == null ? List.<String>of() : texts) {
            InetSocketAddress address = PeerEgressDnsForwarder.parseUpstream(text);
            if (address == null) {
                refused.add(String.valueOf(text));
            } else {
                kept.add(text.trim());
                parsed.add(address);
            }
        }
        String key = String.join(",", kept) + "|" + String.join(",", refused);
        if (!key.equals(upstreamsLogged)) {
            upstreamsLogged = key;
            if (!refused.isEmpty()) {
                log.warn("[peer-egress-consumer] DNS upstreams ignored, not literal addresses: {}", refused.size());
            }
            noUpstreamLogged = false;
        }
        upstreamTexts = List.copyOf(kept);
        upstreams = List.copyOf(parsed);
    }

    synchronized Stats stats() {
        return new Stats(Ipv4Cidr.format(listen), upstreamTexts,
                counters.answered(), counters.forwarded(), counters.failed());
    }

    synchronized int connectionCount() {
        return connections.size();
    }

    private synchronized boolean isClosed() {
        return closed;
    }

    /**
     * One packet from the TUN for the listen address's port 53, from a source already found to be
     * this machine. Called under the consumer's monitor.
     */
    synchronized void handle(byte[] packet, int protocol, List<PeerEgressRule> rules, String meshCidr, long nowMs) {
        if (closed) {
            return;
        }
        if (protocol == PeerEgressDatagram.IPV4_PROTOCOL_UDP) {
            handleUdp(packet, rules, meshCidr, nowMs);
        } else if (protocol == PeerEgressSegment.IPV4_PROTOCOL_TCP) {
            handleTcp(packet, rules, meshCidr, nowMs);
        }
    }

    // --------------------------------------------------------------------------------------------
    // UDP
    // --------------------------------------------------------------------------------------------

    private void handleUdp(byte[] packet, List<PeerEgressRule> rules, String meshCidr, long nowMs) {
        PeerEgressDatagram.Datagram query = PeerEgressDatagram.parse(packet);
        if (query == null) {
            return;
        }
        PeerEgressDnsMessage.Result result =
                PeerEgressDnsMessage.respond(rules, meshCidr, pool, query.payload(), nowMs);
        switch (result.kind()) {
            case ANSWER -> {
                count(result);
                writeUdp(query, result.response());
            }
            case FORWARD -> forward(query.payload(), false, reply -> {
                writeUdp(query, reply);
                return true;
            });
            default -> {
                // Dropped: a response, or too short to be anything.
            }
        }
    }

    /** The answer as a datagram from the listen address to the port the query came from. */
    private void writeUdp(PeerEgressDatagram.Datagram query, byte[] answer) {
        tun.write(PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(
                listen, query.sourceIp(), PORT, query.sourcePort(), answer)));
    }

    private void count(PeerEgressDnsMessage.Result result) {
        if (result.exhausted()) {
            counters.failed.incrementAndGet();
        } else {
            counters.answered.incrementAndGet();
        }
    }

    // --------------------------------------------------------------------------------------------
    // Forwarding
    // --------------------------------------------------------------------------------------------

    /**
     * Sends a query on to the upstreams off this thread, and delivers the reply -- or, when every
     * upstream failed, a SERVFAIL built here -- under this lock. Counted when delivered: a TCP
     * connection that went away meanwhile is owed nothing.
     */
    private void forward(byte[] query, boolean tcp, Delivery delivery) {
        List<InetSocketAddress> targets = upstreams;
        if (targets.isEmpty()) {
            if (!noUpstreamLogged) {
                noUpstreamLogged = true;
                log.warn("[peer-egress-consumer] no DNS upstream to forward to; forwarded queries are answered SERVFAIL");
            }
            fail(query, delivery);
            return;
        }
        if (forwarding >= MAX_FORWARDS) {
            if (!overloadLogged) {
                overloadLogged = true;
                log.warn("[peer-egress-consumer] {} DNS queries already being forwarded; answering SERVFAIL", forwarding);
            }
            fail(query, delivery);
            return;
        }
        overloadLogged = false;
        forwarding++;
        executor.execute(() -> {
            byte[] reply = null;
            try {
                reply = forwarder.forward(query, tcp, targets);
            } catch (RuntimeException broken) {
                // Answered as a failure below: the application asks again.
            }
            synchronized (this) {
                forwarding--;
                if (closed) {
                    return;
                }
                if (reply == null) {
                    fail(query, delivery);
                } else if (delivery.deliver(reply)) {
                    counters.forwarded.incrementAndGet();
                }
            }
        });
    }

    private void fail(byte[] query, Delivery delivery) {
        byte[] servfail = PeerEgressDnsMessage.servfail(query);
        if (servfail != null && delivery.deliver(servfail)) {
            counters.failed.incrementAndGet();
        }
    }

    // --------------------------------------------------------------------------------------------
    // TCP
    // --------------------------------------------------------------------------------------------

    private static long key(int ip, int port) {
        return (Integer.toUnsignedLong(ip) << 16) | port;
    }

    private void handleTcp(byte[] packet, List<PeerEgressRule> rules, String meshCidr, long nowMs) {
        PeerEgressSegment.Segment segment = PeerEgressSegment.parse(packet);
        if (segment == null) {
            return;
        }
        long key = key(segment.sourceIp(), segment.sourcePort());
        Connection connection = connections.get(key);
        boolean opening = segment.has(PeerEgressSegment.FLAG_SYN) && !segment.has(PeerEgressSegment.FLAG_ACK);
        if (segment.has(PeerEgressSegment.FLAG_RST)) {
            // Dropped at once, answered by nothing.
            connections.remove(key);
            return;
        }
        if (connection == null) {
            // Without a connection only a SYN is welcome; anything else is told there is none.
            if (!opening || connections.size() >= MAX_TCP_CONNECTIONS) {
                write(PeerEgressSegment.buildReset(segment));
                return;
            }
            open(key, segment, nowMs);
            return;
        }
        if (segment.has(PeerEgressSegment.FLAG_SYN)) {
            if (opening && !connection.established && segment.seq() == connection.irs) {
                // The SYN again: the SYN-ACK was lost.
                sendSynAck(connection);
            } else if (opening) {
                // A new SYN on a four-tuple still held: the client reused the port.
                connections.remove(key);
                open(key, segment, nowMs);
            }
            return;
        }
        if (segment.has(PeerEgressSegment.FLAG_ACK)) {
            acknowledge(connection, segment.ack(), nowMs);
        }
        if (connection.established) {
            receive(key, connection, segment, rules, meshCidr, nowMs);
        }
        if (connection.finSent && connection.finAcked && connection.peerFin) {
            connections.remove(key);
        }
    }

    private void open(long key, PeerEgressSegment.Segment syn, long nowMs) {
        int peerMss = syn.mss() > 0 ? syn.mss() : PeerEgressSegment.DEFAULT_MSS;
        Connection connection = new Connection(syn.sourceIp(), syn.sourcePort(), random.nextInt(), syn.seq(),
                Math.min(peerMss, TCP_MSS), nowMs);
        connections.put(key, connection);
        sendSynAck(connection);
        connection.retransmitAtMs = nowMs + RETRANSMIT_MS;
    }

    /** Takes what the peer acknowledged off what is owed to it. */
    private void acknowledge(Connection connection, int ack, long nowMs) {
        if (!connection.established) {
            if (ack == connection.iss + 1) {
                connection.established = true;
                connection.retries = 0;
                connection.retransmitAtMs = Long.MAX_VALUE;
            }
            return;
        }
        int acked = ack - connection.sndBase;
        if (acked <= 0 || acked > connection.sent + (connection.finSent ? 1 : 0)) {
            // Old, or beyond anything sent: moves nothing.
            return;
        }
        int data = Math.min(acked, connection.sent);
        connection.out.drop(data);
        connection.sndBase += data;
        connection.sent -= data;
        if (connection.finSent && acked == data + 1) {
            connection.finAcked = true;
        }
        connection.retries = 0;
        connection.retransmitAtMs = connection.outstanding() ? nowMs + RETRANSMIT_MS : Long.MAX_VALUE;
    }

    /** In-order data and FIN; anything out of order is dropped and the current ACK sent again. */
    private void receive(long key, Connection connection, PeerEgressSegment.Segment segment,
            List<PeerEgressRule> rules, String meshCidr, long nowMs) {
        byte[] payload = segment.payload();
        boolean fin = segment.has(PeerEgressSegment.FLAG_FIN);
        boolean acknowledge = false;
        long writesBefore = writes;
        if (payload.length > 0 || fin) {
            acknowledge = true;
            // How much of the segment was already received: a retransmission overlapping the next
            // expected byte is taken from there on, which is still in order.
            int already = connection.rcvNxt - segment.seq();
            boolean inOrder = !connection.peerFin && already >= 0
                    && (already < payload.length || (already == payload.length && fin));
            if (inOrder) {
                int fresh = payload.length - already;
                connection.rcvNxt += fresh;
                if (fin) {
                    connection.rcvNxt++;
                    connection.peerFin = true;
                }
                if (!connection.finSent) {
                    connection.in.append(payload, already, fresh);
                    extractQueries(key, connection, rules, meshCidr, nowMs);
                }
                // After this side's FIN nothing more can be answered; the data is acknowledged and
                // let go.
            }
        }
        flush(connection, nowMs);
        // Anything written since this segment arrived -- an answer here, or one a forward that came
        // back at once delivered -- carried the current ACK; otherwise it goes on its own.
        if (acknowledge && writes == writesBefore) {
            sendFlags(connection, PeerEgressSegment.FLAG_ACK, connection.sndNxt());
        }
    }

    /** Cuts whole length-prefixed queries off the received bytes and gives each its place in line. */
    private void extractQueries(long key, Connection connection, List<PeerEgressRule> rules, String meshCidr,
            long nowMs) {
        while (connection.in.length >= 2) {
            int length = PeerEgressDnsMessage.u16(connection.in.data, 0);
            if (connection.in.length < 2 + length) {
                return;
            }
            byte[] query = Arrays.copyOfRange(connection.in.data, 2, 2 + length);
            connection.in.drop(2 + length);
            connection.lastQueryMs = nowMs;
            PeerEgressDnsMessage.Result result = PeerEgressDnsMessage.respond(rules, meshCidr, pool, query, nowMs);
            switch (result.kind()) {
                case ANSWER -> {
                    count(result);
                    connection.slots.add(new Slot(result.response()));
                }
                case FORWARD -> {
                    // Its place is held: the answers behind it wait for it, in the order they came.
                    Slot slot = new Slot(null);
                    connection.slots.add(slot);
                    forward(query, true, reply -> {
                        if (connections.get(key) != connection || connection.finSent) {
                            return false;
                        }
                        slot.answer = reply;
                        flush(connection, clock.getAsLong());
                        return true;
                    });
                }
                default -> {
                    // Dropped: nothing is owed for it, and nothing waits on it.
                }
            }
        }
    }

    /**
     * Writes what is owed, in order, and a FIN once nothing more is: the peer closed its side, or
     * the connection went idle. Reports whether anything was sent, which carries the current ACK.
     *
     * <p>The peer's window is not tracked: an application on this machine receives into far more
     * than one DNS answer.
     */
    private boolean flush(Connection connection, long nowMs) {
        while (!connection.slots.isEmpty() && connection.slots.peekFirst().answer != null) {
            byte[] answer = connection.slots.pollFirst().answer;
            connection.out.append(new byte[] {(byte) (answer.length >>> 8), (byte) answer.length}, 0, 2);
            connection.out.append(answer, 0, answer.length);
        }
        boolean sentAny = false;
        while (connection.sent < connection.out.length && !connection.finSent) {
            int length = Math.min(connection.mss, connection.out.length - connection.sent);
            sendData(connection, connection.sent, length);
            connection.sent += length;
            sentAny = true;
            arm(connection, nowMs);
        }
        if (!connection.finSent && (connection.peerFin || connection.closeWanted)
                && connection.slots.isEmpty() && connection.sent == connection.out.length) {
            connection.finSent = true;
            connection.finSentAtMs = nowMs;
            sendFlags(connection, PeerEgressSegment.FLAG_FIN | PeerEgressSegment.FLAG_ACK,
                    connection.sndBase + connection.out.length);
            sentAny = true;
            arm(connection, nowMs);
        }
        return sentAny;
    }

    /** Starts the retransmission clock when nothing was outstanding before. */
    private static void arm(Connection connection, long nowMs) {
        if (connection.retransmitAtMs == Long.MAX_VALUE) {
            connection.retransmitAtMs = nowMs + RETRANSMIT_MS;
            connection.retries = 0;
        }
    }

    /**
     * Retransmission and idle close. The oldest unacknowledged segment is sent again after a
     * second, three times, and then the connection is reset; a connection with no new and no
     * unanswered query for ten seconds gets a FIN, and one whose peer has not closed its side ten
     * seconds after that FIN was acknowledged is reset.
     */
    synchronized void onTick(long nowMs) {
        if (closed) {
            return;
        }
        for (Map.Entry<Long, Connection> entry : new ArrayList<>(connections.entrySet())) {
            Connection connection = entry.getValue();
            if (nowMs >= connection.retransmitAtMs) {
                if (connection.retries >= MAX_RETRANSMITS) {
                    reset(connection);
                    connections.remove(entry.getKey());
                    continue;
                }
                connection.retries++;
                connection.retransmitAtMs = nowMs + RETRANSMIT_MS;
                if (!connection.established) {
                    sendSynAck(connection);
                } else if (connection.sent > 0) {
                    sendData(connection, 0, Math.min(connection.mss, connection.sent));
                } else if (connection.finSent && !connection.finAcked) {
                    sendFlags(connection, PeerEgressSegment.FLAG_FIN | PeerEgressSegment.FLAG_ACK,
                            connection.sndBase + connection.out.length);
                }
            }
            if (!connection.established) {
                continue;
            }
            if (!connection.finSent && !connection.closeWanted && connection.slots.isEmpty()
                    && nowMs - connection.lastQueryMs >= IDLE_MS) {
                connection.closeWanted = true;
                flush(connection, nowMs);
            }
            if (connection.finAcked && !connection.peerFin && nowMs - connection.finSentAtMs >= IDLE_MS) {
                reset(connection);
                connections.remove(entry.getKey());
            }
        }
    }

    private void sendSynAck(Connection connection) {
        write(PeerEgressSegment.build(new PeerEgressSegment.Segment(listen, connection.ip, PORT, connection.port,
                connection.iss, connection.rcvNxt, PeerEgressSegment.FLAG_SYN | PeerEgressSegment.FLAG_ACK,
                WINDOW, connection.mss, new byte[0])));
    }

    private void sendData(Connection connection, int offset, int length) {
        write(PeerEgressSegment.build(new PeerEgressSegment.Segment(listen, connection.ip, PORT, connection.port,
                connection.sndBase + offset, connection.rcvNxt,
                PeerEgressSegment.FLAG_ACK | PeerEgressSegment.FLAG_PSH, WINDOW, 0,
                Arrays.copyOfRange(connection.out.data, offset, offset + length))));
    }

    private void sendFlags(Connection connection, int flags, int seq) {
        write(PeerEgressSegment.build(new PeerEgressSegment.Segment(listen, connection.ip, PORT, connection.port,
                seq, connection.rcvNxt, flags, WINDOW, 0, new byte[0])));
    }

    /**
     * Gives up on a connection. The sequence is the first unacknowledged one, where the peer's
     * receive window starts unless our acknowledgements were lost.
     */
    private void reset(Connection connection) {
        int seq = connection.established ? connection.sndBase : connection.iss + 1;
        sendFlags(connection, PeerEgressSegment.FLAG_RST | PeerEgressSegment.FLAG_ACK, seq);
    }

    private void write(byte[] packet) {
        writes++;
        tun.write(packet);
    }

    /** Stops answering: connections are forgotten and forwards still out are not delivered. */
    @Override
    public void close() {
        Thread clockThread;
        synchronized (this) {
            closed = true;
            connections.clear();
            clockThread = ticker;
        }
        if (clockThread != null) {
            clockThread.interrupt();
        }
    }
}
