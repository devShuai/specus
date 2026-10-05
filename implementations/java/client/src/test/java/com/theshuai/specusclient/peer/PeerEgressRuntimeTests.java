package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;

/**
 * Fault injection for the egress data plane.
 *
 * <p>The layers below this one are pure and already have conformance suites. What is left to prove
 * is the part that owns real resources: that a refused flow never reaches a socket, that a socket is
 * released on every path including the ones nobody plans for, and that a revocation takes effect
 * while traffic is in flight rather than at the next idle sweep.
 *
 * <p>The dialer is injected, so an unreachable target, a hung connect and a connection that breaks
 * mid-stream are all produced without a network.
 */
class PeerEgressRuntimeTests {

    private static final long EPOCH = 1_800_000_000_000L;
    private static final Object END_OF_STREAM = new Object();

    /**
     * One end of a socket the runtime believes in. A read blocks until a test supplies data, an end
     * of stream, or an error, which is what lets each failure path be driven on purpose.
     */
    private static final class FakeSocket implements PeerEgressRuntime.Socket {
        private final BlockingQueue<Object> events = new LinkedBlockingQueue<>();
        private final List<byte[]> writes = new ArrayList<>();
        private volatile boolean closed;
        private volatile boolean halfClosed;

        @Override
        public int read(byte[] buffer) throws IOException {
            Object event;
            try {
                event = events.take();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted");
            }
            if (event == END_OF_STREAM) {
                return -1;
            }
            if (event instanceof IOException error) {
                throw error;
            }
            byte[] chunk = (byte[]) event;
            int length = Math.min(chunk.length, buffer.length);
            System.arraycopy(chunk, 0, buffer, 0, length);
            return length;
        }

        @Override
        public void write(byte[] data) {
            synchronized (this) {
                writes.add(data.clone());
            }
        }

        @Override
        public void closeWrite() {
            halfClosed = true;
        }

        @Override
        public void close() {
            if (!closed) {
                closed = true;
                // Unblocks a reader the way a real close does. The runtime drops what the reader
                // reports because the flow has already left the table, which is the check that
                // makes a close race harmless.
                events.offer(new IOException("socket closed"));
            }
        }

        void deliver(byte[] data) {
            events.offer(data);
        }

        void endOfStream() {
            events.offer(END_OF_STREAM);
        }

        void fail(String reason) {
            events.offer(new IOException(reason));
        }

        boolean drained() {
            return events.isEmpty();
        }

        boolean isClosed() {
            return closed;
        }

        boolean isHalfClosed() {
            return halfClosed;
        }

        synchronized List<byte[]> written() {
            return List.copyOf(writes);
        }
    }

    /** Everything a test needs to observe: what was sent, what was dialled, and which sockets. */
    private final class Harness {
        private final List<byte[]> frames = new ArrayList<>();
        private final List<String> dialed = new ArrayList<>();
        private final List<FakeSocket> sockets = new ArrayList<>();
        private volatile IOException dialError;
        /** Blocks the dialer so a test can act while a connect is still in flight. */
        private volatile CountDownLatch gate;

        private final PeerEgressRuntime runtime;

        Harness(String... destinations) {
            runtime = new PeerEgressRuntime(
                    (consumer, frame) -> {
                        synchronized (Harness.this) {
                            frames.add(frame.clone());
                        }
                    },
                    (protocol, host, port, timeoutMs) -> {
                        CountDownLatch waiting;
                        synchronized (Harness.this) {
                            dialed.add(host + ":" + port);
                            waiting = gate;
                        }
                        if (waiting != null) {
                            try {
                                waiting.await();
                            } catch (InterruptedException interrupted) {
                                Thread.currentThread().interrupt();
                            }
                        }
                        IOException failure = dialError;
                        if (failure != null) {
                            throw failure;
                        }
                        FakeSocket socket = new FakeSocket();
                        synchronized (Harness.this) {
                            sockets.add(socket);
                        }
                        return socket;
                    },
                    reader -> Thread.ofVirtual().start(reader),
                    () -> EPOCH);
            runtime.applyPolicy(policy(destinations), PeerEgressAuthorization.Context.defaults(), EPOCH);
        }

        synchronized int dialCount() {
            return dialed.size();
        }

        /** Every host:port dialled, in order. */
        synchronized List<String> dialed() {
            return List.copyOf(dialed);
        }

        synchronized FakeSocket socket(int index) {
            if (index >= sockets.size()) {
                fail("no socket at index " + index + ", only " + sockets.size() + " opened");
            }
            return sockets.get(index);
        }

        synchronized void clearFrames() {
            frames.clear();
        }

        private synchronized List<byte[]> snapshot() {
            return List.copyOf(frames);
        }

        /** Every TCP segment the runtime sent back to a consumer. */
        List<PeerEgressSegment.Segment> segments() {
            List<PeerEgressSegment.Segment> out = new ArrayList<>();
            for (byte[] raw : snapshot()) {
                PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
                if (!frame.accepted() || frame.type() != PeerEgressFrame.TYPE_IP_PACKET) {
                    continue;
                }
                PeerEgressSegment.Segment segment = PeerEgressSegment.parse(frame.body());
                if (segment != null) {
                    out.add(segment);
                }
            }
            return out;
        }

        List<PeerEgressDatagram.Datagram> datagrams() {
            List<PeerEgressDatagram.Datagram> out = new ArrayList<>();
            for (byte[] raw : snapshot()) {
                PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
                if (!frame.accepted() || frame.type() != PeerEgressFrame.TYPE_IP_PACKET) {
                    continue;
                }
                PeerEgressDatagram.Datagram datagram = PeerEgressDatagram.parse(frame.body());
                if (datagram != null) {
                    out.add(datagram);
                }
            }
            return out;
        }

        List<String> rejectCodes() {
            List<String> codes = new ArrayList<>();
            for (byte[] raw : snapshot()) {
                PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
                if (!frame.accepted() || frame.type() != PeerEgressFrame.TYPE_CONTROL) {
                    continue;
                }
                PeerEgressFrame.Control control = PeerEgressFrame.decodeControl(frame.body());
                if (control != null && PeerEgressFrame.CONTROL_FLOW_REJECT.equals(control.type())) {
                    codes.add(control.code());
                }
            }
            return codes;
        }

        boolean sawFlag(int flag) {
            for (PeerEgressSegment.Segment segment : segments()) {
                if (segment.has(flag)) {
                    return true;
                }
            }
            return false;
        }

        boolean sawReset() {
            return sawFlag(PeerEgressSegment.FLAG_RST);
        }

        boolean sawFin() {
            return sawFlag(PeerEgressSegment.FLAG_FIN);
        }

        /** Acknowledges the SYN-ACK so the flow reaches ESTABLISHED. */
        void completeHandshake(long consumer, PeerEgressSegment.Segment syn) {
            List<PeerEgressSegment.Segment> sent = segments();
            if (sent.isEmpty()) {
                fail("no SYN-ACK to acknowledge");
            }
            runtime.handleFrame(consumer, frameFor(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                    syn.sourceIp(), syn.destinationIp(), syn.sourcePort(), syn.destinationPort(),
                    syn.seq() + 1, sent.get(0).seq() + 1, PeerEgressSegment.FLAG_ACK,
                    65535, 0, new byte[0]))), EPOCH);
        }
    }

    /** Polls a condition the reader threads satisfy asynchronously. */
    private static void waitFor(String what, BooleanSupplier condition) {
        // Generous on purpose, and a sleep rather than a spin. The condition is satisfied by
        // another thread, so busy-waiting would compete with the very reader being waited on, and a
        // deadline tight enough to fail on a loaded CI runner would report a scheduling delay as a
        // defect.
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

    private static PeerEgressPolicy policy(String... destinations) {
        String[] cidrs = destinations.length == 0 ? new String[] {"203.0.113.0/24"} : destinations;
        List<PeerEgressPolicy.PeerEgressDestinationRule> rules = new ArrayList<>();
        for (String cidr : cidrs) {
            PeerEgressPolicy.PeerEgressDestinationRule rule =
                    new PeerEgressPolicy.PeerEgressDestinationRule();
            rule.setCidr(cidr);
            rule.setProtocols(List.of("tcp", "udp"));
            // An empty portRanges denies every port, so a rule meant to allow traffic says so.
            rule.setPortRanges(List.of(List.of(1, 65535)));
            rules.add(rule);
        }
        PeerEgressPolicy built = new PeerEgressPolicy();
        built.setEnabled(true);
        built.setScope(PeerEgressPolicy.SCOPE_PUBLIC);
        // 1 and 7 are the consumers of the shared nameBindClosesFlows case.
        built.setAllowedConsumerClientIds(List.of(1L, 7L, 9L));
        built.setDestinationRules(rules);
        return built;
    }

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertTrue(value != null, dotted + " did not parse");
        return value;
    }

    private static PeerEgressSegment.Segment syn(
            String source, int sourcePort, String destination, int destinationPort) {
        return new PeerEgressSegment.Segment(
                address(source), address(destination), sourcePort, destinationPort,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]);
    }

    private static byte[] frameFor(byte[] packet) {
        return PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false, packet);
    }

    /** The happy path, present so the failure cases below are read against something known to work. */
    @Test
    void opensAndForwardsATcpFlow() {
        Harness harness = new Harness();
        PeerEgressSegment.Segment opening = syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(opening)), EPOCH);

        assertEquals(1, harness.dialCount());
        assertTrue(harness.segments().stream().anyMatch(segment ->
                        segment.has(PeerEgressSegment.FLAG_SYN) && segment.has(PeerEgressSegment.FLAG_ACK)),
                "the consumer never received a SYN-ACK");

        harness.completeHandshake(7, opening);
        byte[] payload = "GET / HTTP/1.0\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                opening.sourceIp(), opening.destinationIp(), opening.sourcePort(), opening.destinationPort(),
                opening.seq() + 1, harness.segments().get(0).seq() + 1,
                PeerEgressSegment.FLAG_ACK | PeerEgressSegment.FLAG_PSH, 65535, 0, payload))), EPOCH);

        waitFor("payload to reach the socket", () -> !harness.socket(0).written().isEmpty());
        assertEquals("GET / HTTP/1.0\r\n\r\n",
                new String(harness.socket(0).written().get(0), java.nio.charset.StandardCharsets.US_ASCII));
    }

    /**
     * A refused flow must never reach a socket. Dialing first and checking after would leak a
     * connection to a destination the policy forbids, which is the whole failure this layer exists
     * to prevent.
     */
    @Test
    void refusesBeforeDialing() {
        Harness harness = new Harness("203.0.113.0/24");
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "198.51.100.10", 443))), EPOCH);

        assertEquals(0, harness.dialCount(), "a refused flow opened a socket");
        assertTrue(harness.sawReset(),
                "the consumer was not reset, so its application waits on a flow that will never open");
        assertEquals(List.of(PeerEgressCodes.DEST_DENIED), harness.rejectCodes());
    }

    /**
     * The forced-deny list has to hold against a policy broad enough to cover the address, which is
     * the case it exists for.
     */
    @Test
    void refusesForcedDenyUnderABroadPolicy() {
        Harness harness = new Harness("0.0.0.0/0");
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "169.254.169.254", 80))), EPOCH);

        assertEquals(0, harness.dialCount(), "cloud metadata was dialled");
        assertEquals(List.of(PeerEgressCodes.FORBIDDEN_DESTINATION), harness.rejectCodes());
    }

    /**
     * The quota is charged at reservation, before the connect. A consumer aiming a burst at a black
     * hole would otherwise pass every limit check, because no flow would ever be counted as open.
     */
    @Test
    void chargesQuotaWhileConnectIsInFlight() {
        Harness harness = new Harness();
        PeerEgressPolicy narrowed = policy("203.0.113.0/24");
        PeerEgressPolicy.PeerEgressLimits limits = new PeerEgressPolicy.PeerEgressLimits();
        limits.setMaxFlowsPerConsumer(1);
        narrowed.setLimits(limits);
        harness.runtime.applyPolicy(narrowed, PeerEgressAuthorization.Context.defaults(), EPOCH);

        harness.gate = new CountDownLatch(1);
        Thread.ofVirtual().start(() -> harness.runtime.handleFrame(7,
                frameFor(PeerEgressSegment.build(syn("100.96.0.1", 40000, "203.0.113.10", 443))), EPOCH));
        waitFor("the first connect to start", () -> harness.dialCount() == 1);

        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40001, "203.0.113.10", 443))), EPOCH);

        assertEquals(1, harness.dialCount(),
                "the second flow dialled despite the quota being held by a pending connect");
        assertEquals(List.of(PeerEgressCodes.LIMIT_EXCEEDED), harness.rejectCodes());
        harness.gate.countDown();
    }

    /**
     * New flows come out of a bucket of 128 per consumer, refused the way the concurrency caps refuse.
     * Only a new flow everything else admitted takes a token: a retransmitted SYN, a frame racing the
     * flow it belongs to and a refused attempt take nothing, and one consumer's burst leaves
     * another's bucket alone.
     */
    @Test
    void limitsHowFastAConsumerOpensFlows() {
        Harness harness = new Harness();
        // Concurrency caps above the bucket, so what refuses the 129th flow is the rate.
        PeerEgressPolicy roomy = policy("203.0.113.0/24");
        PeerEgressPolicy.PeerEgressLimits limits = new PeerEgressPolicy.PeerEgressLimits();
        limits.setMaxFlowsPerConsumer(4 * PeerEgressFlowRate.CAPACITY);
        limits.setMaxConcurrentFlows(8 * PeerEgressFlowRate.CAPACITY);
        roomy.setLimits(limits);
        harness.runtime.applyPolicy(roomy, PeerEgressAuthorization.Context.defaults(), EPOCH);
        long[] now = {5_000};
        harness.runtime.flowRateClock = () -> now[0];

        PeerEgressSegment.Segment first = syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(first)), EPOCH);
        for (int port = 40001; port < 40000 + PeerEgressFlowRate.CAPACITY - 1; port++) {
            harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                    syn("100.96.0.1", port, "203.0.113.10", 443))), EPOCH);
        }
        assertEquals(PeerEgressFlowRate.CAPACITY - 1, harness.dialCount());

        for (int retransmit = 0; retransmit < 3; retransmit++) {
            harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(first)), EPOCH);
        }
        harness.runtime.openTcpFlow(7, new PeerEgressFlowTable.Key(PeerEgressSegment.IPV4_PROTOCOL_TCP,
                first.sourceIp(), first.sourcePort(), first.destinationIp(), first.destinationPort()), first, EPOCH);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 50000, "198.51.100.10", 443))), EPOCH);
        assertEquals(PeerEgressFlowRate.CAPACITY - 1, harness.dialCount());
        assertEquals(List.of(PeerEgressCodes.DEST_DENIED), harness.rejectCodes());

        harness.clearFrames();
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40127, "203.0.113.10", 443))), EPOCH);
        assertEquals(PeerEgressFlowRate.CAPACITY, harness.dialCount(),
                "the 128th new flow was refused, so something other than a new flow took a token");
        assertTrue(harness.rejectCodes().isEmpty());

        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40128, "203.0.113.10", 443))), EPOCH);
        assertEquals(PeerEgressFlowRate.CAPACITY, harness.dialCount(), "the 129th new flow was dialled");
        assertEquals(List.of(PeerEgressCodes.LIMIT_EXCEEDED), harness.rejectCodes());
        assertTrue(harness.sawReset(), "the refused flow was not reset");
        assertEquals(1L, harness.runtime.rejections().cumulativeCounts().get(PeerEgressCodes.LIMIT_EXCEEDED));

        harness.runtime.handleFrame(9, frameFor(PeerEgressSegment.build(
                syn("100.96.0.2", 40000, "203.0.113.10", 443))), EPOCH);
        assertEquals(PeerEgressFlowRate.CAPACITY + 1, harness.dialCount(),
                "one consumer's burst refused another's flow");

        // A token takes 15.625 ms to come back.
        now[0] += 15;
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40129, "203.0.113.10", 443))), EPOCH);
        assertEquals(PeerEgressFlowRate.CAPACITY + 1, harness.dialCount(), "a token came back within 15 ms");
        now[0] += 1;
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40130, "203.0.113.10", 443))), EPOCH);
        assertEquals(PeerEgressFlowRate.CAPACITY + 2, harness.dialCount(), "no token came back after 16 ms");

        harness.runtime.shutdown(EPOCH);
    }

    /**
     * A connect that fails is not a refusal. Reporting it as one would send an operator hunting for
     * a policy rule that never fired, and would inflate the refusal counts the server aggregates.
     */
    @Test
    void separatesAnUnreachableTargetFromARefusal() {
        Harness harness = new Harness();
        harness.dialError = new IOException("connection refused");

        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "203.0.113.10", 443))), EPOCH);

        assertTrue(harness.sawReset(), "an unreachable target left the consumer without a reset");
        assertTrue(harness.rejectCodes().isEmpty(), "a network failure was reported as a refusal");
        assertTrue(harness.runtime.rejections().drainCounts().isEmpty(),
                "a network failure entered the refusal aggregate");
        // The reservation must come back, or a flapping destination would exhaust the quota.
        assertEquals(0, harness.runtime.flowCount(), "flows left after a failed connect");
    }

    /**
     * A connection that dies mid-stream has to reach the consumer as a reset. Silence would leave
     * the application waiting for data that is never coming.
     */
    @Test
    void resetsWhenTheConnectionBreaks() {
        Harness harness = new Harness();
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "203.0.113.10", 443))), EPOCH);
        waitFor("the flow to open", () -> harness.runtime.flowCount() == 1);
        harness.clearFrames();

        harness.socket(0).fail("connection reset by peer");

        waitFor("the flow to be released", () -> harness.runtime.flowCount() == 0);
        assertTrue(harness.sawReset(), "a broken connection produced no reset for the consumer");
        assertTrue(harness.socket(0).isClosed(), "the socket was not closed");
    }

    /**
     * A clean end of stream is a half-close, not a failure. Turning it into a reset would discard a
     * response the consumer is still entitled to read.
     */
    @Test
    void turnsSocketEndOfStreamIntoAFin() {
        Harness harness = new Harness();
        PeerEgressSegment.Segment opening = syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(opening)), EPOCH);
        waitFor("the flow to open", () -> harness.runtime.flowCount() == 1);
        harness.completeHandshake(7, opening);
        harness.clearFrames();

        harness.socket(0).endOfStream();

        waitFor("a FIN for the consumer", harness::sawFin);
        assertFalse(harness.sawReset(), "a clean end of stream was reported as a reset");
    }

    /**
     * The egress closed first and the consumer answered with its own FIN: the flow is in TIME_WAIT.
     * Its socket is closed and its quota is free at once; the entry stays to answer a retransmitted
     * FIN.
     */
    @Test
    void freesTheQuotaOfAFlowInTimeWait() throws Exception {
        Harness harness = new Harness();
        PeerEgressSegment.Segment opening = syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(opening)), EPOCH);
        waitFor("the flow to open", () -> harness.runtime.flowCount() == 1);
        harness.completeHandshake(7, opening);
        harness.clearFrames();

        harness.socket(0).endOfStream();
        waitFor("a FIN for the consumer", harness::sawFin);
        PeerEgressSegment.Segment fin = harness.segments().stream()
                .filter(segment -> segment.has(PeerEgressSegment.FLAG_FIN)).reduce((a, b) -> b).orElseThrow();
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                opening.sourceIp(), opening.destinationIp(), opening.sourcePort(), opening.destinationPort(),
                opening.seq() + 1, fin.seq() + 1, PeerEgressSegment.FLAG_ACK | PeerEgressSegment.FLAG_FIN,
                65535, 0, new byte[0]))), EPOCH);

        assertEquals(0, harness.runtime.flowCount(), "a flow in TIME_WAIT still counts");
        java.lang.reflect.Field field = PeerEgressRuntime.class.getDeclaredField("flows");
        field.setAccessible(true);
        PeerEgressFlowTable table = (PeerEgressFlowTable) field.get(harness.runtime);
        assertEquals(0, table.countFor(7));
        assertNotNull(table.lookup(new PeerEgressFlowTable.Key(PeerEgressSegment.IPV4_PROTOCOL_TCP,
                        opening.sourceIp(), opening.sourcePort(), opening.destinationIp(), opening.destinationPort())),
                "the TIME_WAIT entry went before its timer, so a retransmitted FIN would go unanswered");
        assertTrue(harness.socket(0).isClosed(), "the socket of a finished flow was kept open through TIME_WAIT");
    }

    /**
     * A socket that ends while the handshake is still in flight owes the consumer a FIN as soon as
     * the handshake completes. Sending it earlier would run ahead of a sequence space the consumer
     * has not acknowledged; never sending it leaves the flow open until the idle timer collects it,
     * with the consumer waiting on a connection that is already over.
     */
    @Test
    void defersAFinUntilTheHandshakeCompletes() {
        Harness harness = new Harness();
        PeerEgressSegment.Segment opening = syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(opening)), EPOCH);
        waitFor("the flow to open", () -> harness.runtime.flowCount() == 1);

        harness.socket(0).endOfStream();
        // Wait for the reader to have taken the event, so the check below is about what the state
        // machine decided rather than about whether it has looked yet.
        waitFor("the reader to observe the end of stream", () -> harness.socket(0).drained());
        assertFalse(harness.sawFin(), "a FIN was sent before the consumer acknowledged the SYN-ACK");

        harness.completeHandshake(7, opening);
        waitFor("the deferred FIN", harness::sawFin);
        assertFalse(harness.sawReset(), "the deferred close was turned into a reset");
    }

    /** Revocation must take effect while traffic is in flight, not at the next idle sweep. */
    @Test
    void revokesLiveFlowsImmediately() {
        Harness harness = new Harness();
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "203.0.113.10", 443))), EPOCH);
        harness.runtime.handleFrame(9, frameFor(PeerEgressSegment.build(
                syn("100.96.0.2", 40000, "203.0.113.11", 443))), EPOCH);
        waitFor("both flows to open", () -> harness.runtime.flowCount() == 2);
        harness.clearFrames();

        harness.runtime.revokeConsumer(7, EPOCH);

        assertEquals(1, harness.runtime.flowCount(), "the other consumer was touched");
        assertTrue(harness.socket(0).isClosed(), "the revoked flow's socket stayed open");
        assertFalse(harness.socket(1).isClosed(), "revoking one consumer closed another's socket");
        assertEquals(List.of(PeerEgressCodes.PEER_ACL_DENIED), harness.rejectCodes());
        assertTrue(harness.sawReset(), "the revoked consumer got no reset");
    }

    /** Turning the switch off means now, not at the next idle sweep. */
    @Test
    void drainsWhenTheSwitchGoesOff() {
        Harness harness = new Harness();
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "203.0.113.10", 443))), EPOCH);
        waitFor("the flow to open", () -> harness.runtime.flowCount() == 1);

        PeerEgressPolicy disabled = policy("203.0.113.0/24");
        disabled.setEnabled(false);
        harness.runtime.applyPolicy(disabled, PeerEgressAuthorization.Context.defaults(), EPOCH);

        assertEquals(0, harness.runtime.flowCount(), "a flow survived the switch going off");
        assertTrue(harness.socket(0).isClosed(), "a socket survived the switch going off");

        // A further attempt must be refused rather than opening on a disabled egress.
        harness.clearFrames();
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40002, "203.0.113.10", 443))), EPOCH);
        assertEquals(List.of(PeerEgressCodes.DISABLED), harness.rejectCodes());
    }

    /** A narrowed policy closes the flows it no longer covers, and tells each one why. */
    @Test
    void closesFlowsANarrowedPolicyDrops() {
        Harness harness = new Harness("203.0.113.0/24", "198.51.100.0/24");
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "203.0.113.10", 443))), EPOCH);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40001, "198.51.100.10", 443))), EPOCH);
        waitFor("both flows to open", () -> harness.runtime.flowCount() == 2);
        harness.clearFrames();

        harness.runtime.applyPolicy(policy("203.0.113.0/24"),
                PeerEgressAuthorization.Context.defaults(), EPOCH);

        assertEquals(1, harness.runtime.flowCount(), "the flow the policy still covers was closed");
        assertEquals(List.of(PeerEgressCodes.DEST_DENIED), harness.rejectCodes());
    }

    /**
     * A purge speaks for its sender's flows. Acting on it for everyone would let any consumer tear
     * down every other consumer's traffic with one message.
     */
    @Test
    void purgeOnlyTouchesItsSender() {
        Harness harness = new Harness();
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "203.0.113.10", 443))), EPOCH);
        harness.runtime.handleFrame(9, frameFor(PeerEgressSegment.build(
                syn("100.96.0.2", 40000, "203.0.113.10", 443))), EPOCH);
        waitFor("both flows to open", () -> harness.runtime.flowCount() == 2);

        byte[] body = PeerEgressFrame.encodeControl(
                PeerEgressFrame.Control.flowPurge(List.of("203.0.113.0/24"), ""));
        harness.runtime.handleFrame(7,
                PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false, body), EPOCH);

        assertEquals(1, harness.runtime.flowCount(), "a purge closed more than its sender's flows");
        assertFalse(harness.socket(1).isClosed(),
                "one consumer's purge closed another consumer's socket");
    }

    /**
     * UDP has no handshake, so the first datagram is the authorization point and the reply path has
     * to be built from the flow key rather than from whatever the socket reports.
     */
    @Test
    void carriesAUdpSession() {
        Harness harness = new Harness();
        PeerEgressDatagram.Datagram query = new PeerEgressDatagram.Datagram(
                address("100.96.0.1"), address("203.0.113.53"), 51000, 53,
                "query".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        harness.runtime.handleFrame(7, frameFor(PeerEgressDatagram.build(query)), EPOCH);

        waitFor("the query to reach the socket",
                () -> harness.dialCount() == 1 && harness.socket(0).written().size() == 1);
        harness.socket(0).deliver("answer".getBytes(java.nio.charset.StandardCharsets.US_ASCII));

        waitFor("the reply to reach the consumer", () -> !harness.datagrams().isEmpty());
        PeerEgressDatagram.Datagram reply = harness.datagrams().get(0);
        assertEquals(query.destinationIp(), reply.sourceIp(), "the reply did not mirror the addresses");
        assertEquals(query.sourceIp(), reply.destinationIp(), "the reply did not mirror the addresses");
        assertEquals(query.destinationPort(), reply.sourcePort());
        assertEquals(query.sourcePort(), reply.destinationPort());
        assertEquals("answer",
                new String(reply.payload(), java.nio.charset.StandardCharsets.US_ASCII));
    }

    /** Nothing in UDP says a session ended, so without this the socket would be held forever. */
    @Test
    void expiresAnIdleUdpSession() {
        Harness harness = new Harness();
        PeerEgressPolicy timed = policy("203.0.113.0/24");
        PeerEgressPolicy.PeerEgressLimits limits = new PeerEgressPolicy.PeerEgressLimits();
        limits.setIdleTimeoutSeconds(30);
        timed.setLimits(limits);
        harness.runtime.applyPolicy(timed, PeerEgressAuthorization.Context.defaults(), EPOCH);

        harness.runtime.handleFrame(7, frameFor(PeerEgressDatagram.build(
                new PeerEgressDatagram.Datagram(address("100.96.0.1"), address("203.0.113.53"),
                        51000, 53, "query".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))), EPOCH);
        waitFor("the session to open", () -> harness.runtime.flowCount() == 1);

        harness.runtime.onTick(EPOCH + 10_000);
        assertEquals(1, harness.runtime.flowCount(), "the session expired before its timeout");
        harness.runtime.onTick(EPOCH + 31_000);
        assertEquals(0, harness.runtime.flowCount(), "the session outlived its idle timeout");
        assertTrue(harness.socket(0).isClosed(), "an expired session left its socket open");
        // An expiring session is the normal end of life, not something to report as blocked traffic.
        assertTrue(harness.runtime.rejections().drainCounts().isEmpty(),
                "idle expiry entered the refusal aggregate");
    }

    /**
     * A stray segment for a flow that was never opened gets a reset, which is what tells a consumer
     * holding stale state to give up rather than retry into silence.
     */
    @Test
    void resetsSegmentsForUnknownFlows() {
        Harness harness = new Harness();
        byte[] stray = PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address("100.96.0.1"), address("203.0.113.10"), 40000, 443,
                5000, 9000, PeerEgressSegment.FLAG_ACK, 65535, 0,
                "stale".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        harness.runtime.handleFrame(7, frameFor(stray), EPOCH);

        assertEquals(0, harness.dialCount(), "a stray segment opened a socket");
        assertTrue(harness.sawReset(), "a stray segment got no reset");
    }

    /** Shutdown has to have stopped traffic by the time it returns, not merely have asked it to. */
    @Test
    void shutdownReleasesEverything() {
        Harness harness = new Harness();
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "203.0.113.10", 443))), EPOCH);
        harness.runtime.handleFrame(7, frameFor(PeerEgressDatagram.build(
                new PeerEgressDatagram.Datagram(address("100.96.0.1"), address("203.0.113.53"),
                        51000, 53, "query".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))), EPOCH);
        waitFor("both flows to open", () -> harness.runtime.flowCount() == 2);

        harness.runtime.shutdown(EPOCH);

        assertEquals(0, harness.runtime.flowCount(), "flows survived shutdown");
        assertTrue(harness.socket(0).isClosed(), "socket 0 survived shutdown");
        assertTrue(harness.socket(1).isClosed(), "socket 1 survived shutdown");

        harness.clearFrames();
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40003, "203.0.113.10", 443))), EPOCH);
        assertEquals(2, harness.dialCount(), "a shut-down runtime opened a new socket");
    }

    /**
     * Forwarding a protocol the egress does not account for would leak traffic past the policy, so
     * it is refused rather than passed through.
     */
    @Test
    void refusesProtocolsItDoesNotCarry() {
        Harness harness = new Harness("0.0.0.0/0");
        // A minimal ICMP echo request; only the IPv4 header matters to the dispatch.
        byte[] packet = new byte[28];
        packet[0] = 0x45;
        packet[3] = 28;
        packet[9] = 1;
        System.arraycopy(new byte[] {100, 96, 0, 1}, 0, packet, 12, 4);
        System.arraycopy(new byte[] {(byte) 203, 0, 113, 10}, 0, packet, 16, 4);
        packet[20] = 8;

        harness.runtime.handleFrame(7, frameFor(packet), EPOCH);

        assertEquals(0, harness.dialCount(), "an unsupported protocol opened a socket");
        assertEquals(List.of(PeerEgressCodes.PROTOCOL_DENIED), harness.rejectCodes());
    }

    /** A half-close reaches the real socket as one, so a response still in flight is not discarded. */
    @Test
    void halfClosesTheSocketWhenTheConsumerFinishesSending() {
        Harness harness = new Harness();
        PeerEgressSegment.Segment opening = syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(opening)), EPOCH);
        waitFor("the flow to open", () -> harness.runtime.flowCount() == 1);
        harness.completeHandshake(7, opening);

        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                opening.sourceIp(), opening.destinationIp(), opening.sourcePort(), opening.destinationPort(),
                opening.seq() + 1, harness.segments().get(0).seq() + 1,
                PeerEgressSegment.FLAG_ACK | PeerEgressSegment.FLAG_FIN, 65535, 0, new byte[0]))), EPOCH);

        assertTrue(harness.socket(0).isHalfClosed(), "the write side was not half-closed");
        assertFalse(harness.socket(0).isClosed(), "the whole socket was closed on a half-close");
    }

    /**
     * Two frames for the same four-tuple can both find no flow before either has reserved one. Only
     * the call that created the reservation may dial: two sockets on one entry would leak the loser
     * and leave two state machines answering for the same connection.
     */
    @Test
    void dialsOnceForOneFlow() throws Exception {
        Harness harness = new Harness();
        harness.gate = new CountDownLatch(1);

        PeerEgressSegment.Segment opening = syn("100.96.0.1", 40000, "203.0.113.10", 443);
        PeerEgressFlowTable.Key key = new PeerEgressFlowTable.Key(
                PeerEgressSegment.IPV4_PROTOCOL_TCP, opening.sourceIp(), opening.sourcePort(),
                opening.destinationIp(), opening.destinationPort());

        Thread first = Thread.ofVirtual().start(() -> harness.runtime.openTcpFlow(7, key, opening, EPOCH));
        waitFor("the first connect to start", () -> harness.dialCount() == 1);

        // The racing second attempt, which the reservation must already have claimed. Run in its own
        // thread: an implementation that dials again would block on the gate, and a hung test says
        // far less than a counted one.
        Thread second = Thread.ofVirtual().start(() -> harness.runtime.openTcpFlow(7, key, opening, EPOCH));
        second.join(1000);

        assertEquals(1, harness.dialCount(), "dialled more than once for one flow");
        assertEquals(1, harness.runtime.flowCount(), "more than one flow for one four-tuple");

        harness.gate.countDown();
        first.join(2000);
    }

    private static void bindName(Harness harness, long consumer, String address, String name) {
        harness.runtime.handleFrame(consumer, PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false,
                PeerEgressFrame.encodeControl(PeerEgressFrame.Control.nameBind(address, name))), EPOCH);
    }

    private static java.util.function.Function<String, List<Integer>> resolvingTo(String... addresses) {
        return name -> {
            List<Integer> resolved = new ArrayList<>();
            for (String text : addresses) {
                resolved.add(address(text));
            }
            return resolved;
        };
    }

    /**
     * A flow to a bound address is dialled to what the name resolves to, and the flow keeps the
     * fake address, so the replies come back from the address the consumer's application connected to.
     */
    @Test
    void dialsTheResolvedAddressOfABoundName() {
        Harness harness = new Harness();
        harness.runtime.resolve = resolvingTo("127.0.0.1", "203.0.113.10");
        bindName(harness, 7, "198.18.0.5", "example.com");

        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "198.18.0.5", 443))), EPOCH);

        assertEquals(List.of("203.0.113.10:443"), harness.dialed());
        List<PeerEgressSegment.Segment> segments = harness.segments();
        assertTrue(!segments.isEmpty() && segments.get(0).sourceIp() == address("198.18.0.5"),
                "the SYN-ACK did not come from the fake address");
    }

    /**
     * A name that resolves only to what the policy forbids is refused, which is where DNS rebinding
     * is stopped: nothing is dialled.
     */
    @Test
    void refusesANameThatResolvesToAForbiddenAddress() {
        Harness harness = new Harness();
        harness.runtime.resolve = resolvingTo("127.0.0.1");
        bindName(harness, 7, "198.18.0.5", "rebind.example");

        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "198.18.0.5", 443))), EPOCH);

        assertEquals(0, harness.dialCount(), "a name resolving to loopback was dialled");
        assertTrue(harness.sawReset(), "the refused flow was not reset");
        assertEquals(List.of(PeerEgressCodes.FORBIDDEN_DESTINATION), harness.rejectCodes());
    }

    @Test
    void refusesANameThatDoesNotResolve() {
        Harness harness = new Harness();
        harness.runtime.resolve = name -> {
            throw new IllegalStateException("no such host");
        };
        bindName(harness, 7, "198.18.0.5", "nowhere.example");

        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "198.18.0.5", 443))), EPOCH);

        assertEquals(0, harness.dialCount(), "an unresolved name was dialled");
        assertEquals(List.of(PeerEgressCodes.NAME_UNRESOLVED), harness.rejectCodes());
    }

    /**
     * Bindings are per consumer: one consumer's name for an address says nothing about another's
     * flows to the same address.
     */
    @Test
    void keepsBindingsPerConsumer() {
        Harness harness = new Harness();
        harness.runtime.resolve = resolvingTo("203.0.113.10");
        bindName(harness, 9, "198.18.0.5", "example.com");

        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "198.18.0.5", 443))), EPOCH);

        assertEquals(0, harness.dialCount(), "consumer 7's flow used consumer 9's binding");
        assertTrue(harness.sawReset(), "the unbound fake address was not refused");
    }

    /** A UDP session to a bound address goes to the resolved address too. */
    @Test
    void carriesAUdpSessionToABoundName() {
        Harness harness = new Harness();
        harness.runtime.resolve = resolvingTo("203.0.113.53");
        bindName(harness, 7, "198.18.0.9", "dns.example");

        harness.runtime.handleFrame(7, frameFor(PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(
                address("100.96.0.1"), address("198.18.0.9"), 50000, 53,
                "query".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))), EPOCH);

        waitFor("the datagram to reach the socket",
                () -> harness.dialCount() == 1 && !harness.socket(0).written().isEmpty());
        assertEquals(List.of("203.0.113.53:53"), harness.dialed());
    }

    /**
     * Which flows a name-bind closes and which of them the application is reset on, bound to the
     * {@code nameBindClosesFlows} section of {@code peer-egress-dns-v1.json}. Each flow is a real TCP
     * flow opened through the runtime and answered with a SYN-ACK; the name it remembers is read
     * back. A flow the case says is closed must be gone with its socket closed; one it says is reset
     * must have sent the consumer a RST, and no other may have; and no flow-reject goes out, which
     * would have the consumer drop the flow its next packet reopens.
     */
    @Test
    void nameBindClosesFlowsAsTheSharedVectorSays() throws IOException {
        com.fasterxml.jackson.databind.JsonNode section =
                PeerEgressFakeIpPoolTests.vector().path("nameBindClosesFlows");
        // The fake range is allowed so a flow opened before its name reaches a socket, as it would
        // under a broad policy; that flow is the one the name-bind has to close.
        Harness harness = new Harness("203.0.113.0/24", "198.18.0.0/15");
        harness.runtime.resolve = resolvingTo("203.0.113.10");
        java.util.Map<String, PeerEgressFlowTable.Key> open = new java.util.LinkedHashMap<>();
        java.util.Map<String, Integer> socketOf = new java.util.HashMap<>();
        int sourcePort = 40000;
        com.fasterxml.jackson.databind.JsonNode events = section.path("events");
        com.fasterxml.jackson.databind.JsonNode results = section.path("results");
        assertEquals(events.size(), results.size());
        assertFalse(events.isEmpty(), "no nameBindClosesFlows events");
        for (int index = 0; index < events.size(); index++) {
            com.fasterxml.jackson.databind.JsonNode event = events.get(index);
            com.fasterxml.jackson.databind.JsonNode expected = results.get(index);
            String where = "event " + index + " " + event;
            long consumer = event.path("consumer").asLong();
            String destination = event.path("address").asText();
            if (event.has("open")) {
                int port = sourcePort++;
                String source = "100.96.0." + consumer;
                int dialsBefore = harness.dialCount();
                harness.clearFrames();
                harness.runtime.handleFrame(consumer, frameFor(PeerEgressSegment.build(
                        syn(source, port, destination, 443))), EPOCH);
                PeerEgressFlowTable.Key key = new PeerEgressFlowTable.Key(PeerEgressSegment.IPV4_PROTOCOL_TCP,
                        address(source), port, address(destination), 443);
                assertTrue(harness.runtime.hasFlow(key), where + ": the flow did not open");
                assertEquals(dialsBefore + 1, harness.dialCount(), where);
                assertTrue(harness.sawFlag(PeerEgressSegment.FLAG_SYN), where + ": the flow was not answered");
                com.fasterxml.jackson.databind.JsonNode name = expected.path("name");
                assertEquals(name.isNull() ? null : name.asText(), harness.runtime.flowName(key), where);
                open.put(event.path("open").asText(), key);
                socketOf.put(event.path("open").asText(), dialsBefore);
            } else {
                harness.clearFrames();
                bindName(harness, consumer, destination, event.path("nameBind").asText());
                List<String> closed = new ArrayList<>();
                List<String> reset = new ArrayList<>();
                for (var entry : open.entrySet()) {
                    PeerEgressFlowTable.Key key = entry.getValue();
                    if (!harness.runtime.hasFlow(key)) {
                        closed.add(entry.getKey());
                    }
                    boolean wasReset = harness.segments().stream().anyMatch(segment ->
                            segment.has(PeerEgressSegment.FLAG_RST) && segment.destinationIp() == key.consumerIp()
                                    && segment.destinationPort() == key.consumerPort());
                    if (wasReset) {
                        reset.add(entry.getKey());
                    }
                }
                java.util.Collections.sort(closed);
                java.util.Collections.sort(reset);
                List<String> wantClosed = new ArrayList<>();
                expected.path("closed").forEach(id -> wantClosed.add(id.asText()));
                List<String> wantReset = new ArrayList<>();
                expected.path("reset").forEach(id -> wantReset.add(id.asText()));
                assertEquals(wantClosed, closed, where + ": closed");
                assertEquals(wantReset, reset, where + ": reset");
                for (String id : closed) {
                    assertTrue(harness.socket(socketOf.get(id)).isClosed(), where + ": " + id + "'s socket is open");
                    open.remove(id);
                }
                assertTrue(harness.rejectCodes().isEmpty(), where + ": a name-bind closure told the consumer to drop its side");
            }
        }
    }

    /** policy(destinations) with one domain rule allowing tcp/443 to what match covers. */
    private static PeerEgressPolicy withDomainRule(String match, String... destinations) {
        PeerEgressPolicy built = policy(destinations);
        PeerEgressPolicy.PeerEgressDomainRule rule = new PeerEgressPolicy.PeerEgressDomainRule();
        rule.setMatch(match);
        rule.setProtocols(List.of("tcp"));
        rule.setPortRanges(List.of(List.of(443, 443)));
        built.setDomainRules(List.of(rule));
        return built;
    }

    /**
     * A domain rule admits a flow the consumer opened under a name even though the address the name
     * resolves to is outside every destination rule. Without the rule the same flow is refused at
     * the destination step, and a flow straight to that address is refused even with it: a domain
     * rule grants names, not the addresses they happen to resolve to.
     */
    @Test
    void aDomainRuleAdmitsANamedFlowOutsideTheDestinationRules() {
        Harness granted = new Harness();
        granted.runtime.applyPolicy(withDomainRule("*.example.com", "203.0.113.0/24"),
                PeerEgressAuthorization.Context.defaults(), EPOCH);
        granted.runtime.resolve = resolvingTo("192.0.2.10");
        bindName(granted, 7, "198.18.0.5", "www.example.com");
        granted.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "198.18.0.5", 443))), EPOCH);

        assertEquals(List.of("192.0.2.10:443"), granted.dialed());
        assertTrue(granted.rejectCodes().isEmpty(), "the named flow was refused: " + granted.rejectCodes());
        assertEquals("www.example.com", granted.runtime.flowName(new PeerEgressFlowTable.Key(
                PeerEgressSegment.IPV4_PROTOCOL_TCP, address("100.96.0.1"), 40000, address("198.18.0.5"), 443)));

        granted.clearFrames();
        granted.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40001, "192.0.2.10", 443))), EPOCH);
        assertEquals(1, granted.dialCount(), "a flow to the address alone was admitted by a domain rule");
        assertEquals(List.of(PeerEgressCodes.DEST_DENIED), granted.rejectCodes());

        Harness refused = new Harness("203.0.113.0/24");
        refused.runtime.resolve = resolvingTo("192.0.2.10");
        bindName(refused, 7, "198.18.0.5", "www.example.com");
        refused.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "198.18.0.5", 443))), EPOCH);

        assertEquals(0, refused.dialCount(), "a named flow outside the destination rules was dialled");
        assertTrue(refused.sawReset(), "the refused flow was not reset");
        assertEquals(List.of(PeerEgressCodes.DEST_DENIED), refused.rejectCodes());
    }

    /**
     * A policy refresh judges a named flow as its opening did: the address it was dialled to, with
     * its name. Kept while the domain rule that admitted it stays, even with this node's own pool
     * (which the consumer's fake address is in) forced-denied as it is when the egress runs phase two
     * itself; revoked like any other revocation once the rule is gone. A named flow a destination
     * rule admits is untouched by both.
     */
    @Test
    void aPolicyRefreshWithoutTheDomainRuleRevokesTheNamedFlow() {
        PeerEgressAuthorization.Context ownPoolDenied = new PeerEgressAuthorization.Context(
                "100.96.0.0/11", List.of("198.18.0.0/15"));
        Harness harness = new Harness();
        harness.runtime.applyPolicy(withDomainRule("example.com", "203.0.113.0/24"), ownPoolDenied, EPOCH);
        harness.runtime.resolve = name -> List.of(address(
                name.equals("example.com") ? "192.0.2.10" : "203.0.113.10"));
        bindName(harness, 7, "198.18.0.5", "example.com");
        bindName(harness, 7, "198.18.0.6", "other.example");
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40000, "198.18.0.5", 443))), EPOCH);
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(
                syn("100.96.0.1", 40001, "198.18.0.6", 443))), EPOCH);
        assertEquals(List.of("192.0.2.10:443", "203.0.113.10:443"), harness.dialed());
        assertEquals(2, harness.runtime.flowCount());
        harness.clearFrames();

        harness.runtime.applyPolicy(withDomainRule("example.com", "203.0.113.0/24"), ownPoolDenied, EPOCH);
        assertEquals(2, harness.runtime.flowCount(), "a refresh that kept every grant revoked a named flow");
        assertTrue(harness.rejectCodes().isEmpty(), "a refresh that kept every grant refused: " + harness.rejectCodes());

        harness.runtime.applyPolicy(policy("203.0.113.0/24"), ownPoolDenied, EPOCH);
        assertEquals(1, harness.runtime.flowCount(), "the flow its domain rule admitted survived the rule");
        assertTrue(harness.socket(0).isClosed(), "the revoked named flow's socket stayed open");
        assertFalse(harness.socket(1).isClosed(), "the flow a destination rule admits was closed");
        assertTrue(harness.runtime.hasFlow(new PeerEgressFlowTable.Key(PeerEgressSegment.IPV4_PROTOCOL_TCP,
                address("100.96.0.1"), 40001, address("198.18.0.6"), 443)));
        assertEquals(List.of(PeerEgressCodes.DEST_DENIED), harness.rejectCodes());
        assertTrue(harness.sawReset(), "the revoked named flow got no reset");
    }

    /**
     * The case the name-bind closure exists for: a SYN reaches the egress before its name, and the
     * flow it opens dials the fake address itself. The name-bind closes it while the dial is still
     * in flight, the socket that dial returns is closed, and the retransmitted SYN opens the flow
     * by name. Before, the retransmitted SYN was taken as part of the flow to nowhere.
     */
    @Test
    void aNameBindAfterTheSynReopensTheFlowByName() throws Exception {
        Harness harness = new Harness("203.0.113.0/24", "198.18.0.0/15");
        harness.runtime.resolve = resolvingTo("203.0.113.10");
        PeerEgressSegment.Segment opening = syn("100.96.0.1", 40000, "198.18.0.5", 443);
        PeerEgressFlowTable.Key key = new PeerEgressFlowTable.Key(PeerEgressSegment.IPV4_PROTOCOL_TCP,
                address("100.96.0.1"), 40000, address("198.18.0.5"), 443);
        harness.gate = new CountDownLatch(1);
        Thread early = Thread.ofVirtual().start(() ->
                harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(opening)), EPOCH));
        waitFor("the unbound dial to start", () -> harness.dialCount() == 1);
        assertTrue(harness.runtime.hasFlow(key));

        bindName(harness, 7, "198.18.0.5", "example.com");
        assertFalse(harness.runtime.hasFlow(key), "the flow opened before the name survived its name-bind");
        harness.gate.countDown();
        early.join(5000);
        assertTrue(harness.socket(0).isClosed(), "the socket to the fake address was kept");

        harness.gate = null;
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(opening)), EPOCH);
        assertEquals(List.of("198.18.0.5:443", "203.0.113.10:443"), harness.dialed());
        assertEquals("example.com", harness.runtime.flowName(key));
        assertTrue(harness.segments().stream().anyMatch(segment -> segment.has(PeerEgressSegment.FLAG_SYN)
                && segment.has(PeerEgressSegment.FLAG_ACK) && segment.sourceIp() == address("198.18.0.5")),
                "the retransmitted SYN was not answered from the fake address");
        // Closed silently: a reset here would have the application refuse the connection the
        // name-bind came to rescue.
        assertFalse(harness.sawReset(), "the flow opened before its name was reset");
        assertTrue(harness.rejectCodes().isEmpty());
    }
}
