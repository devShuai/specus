package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The DNS responder where it meets packets: queries written into the TUN go through the real
 * consumer's read path, answers come back as IPv4 packets whose headers and checksums are checked
 * independently here, forwarding goes over real sockets to fake upstreams on this machine, and a TCP
 * session is driven segment by segment.
 */
class PeerEgressDnsResponderTests {

    private static final long EPOCH = 1_800_000_000_000L;
    private static final String VIRTUAL_IP = "100.96.0.1";
    private static final int LISTEN = address("198.18.0.1");
    private static final int CLIENT = address(VIRTUAL_IP);
    private static final int CLIENT_PORT = 40_000;
    private static final int CLIENT_MSS = 1000;

    private final List<AutoCloseable> closeables = new ArrayList<>();

    @AfterEach
    void close() throws Exception {
        for (AutoCloseable closeable : closeables) {
            closeable.close();
        }
    }

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        if (value == null) {
            throw new IllegalArgumentException(dotted);
        }
        return value;
    }

    private static PeerEgressRule rule(String match, String action, Long target) {
        PeerEgressRule value = new PeerEgressRule();
        value.setMatch(match);
        value.setAction(action);
        value.setEgressClientId(target);
        return value;
    }

    private static List<PeerEgressRule> rules() {
        return List.of(rule("example.com", PeerEgressRule.ACTION_EGRESS, 2L),
                rule("*.example.com", PeerEgressRule.ACTION_EGRESS, 3L),
                rule("direct.example.com", PeerEgressRule.ACTION_DIRECT, null));
    }

    /** Runs forwards when told to, so a test decides when an upstream has answered. */
    private static final class Deferred implements Executor {
        private final List<Runnable> tasks = new ArrayList<>();

        @Override
        public synchronized void execute(Runnable task) {
            tasks.add(task);
        }

        void runAll() {
            List<Runnable> pending;
            synchronized (this) {
                pending = new ArrayList<>(tasks);
                tasks.clear();
            }
            pending.forEach(Runnable::run);
        }
    }

    /** A consumer with phase two running and a responder over its pool, writing into a list. */
    private final class Harness {
        final List<byte[]> toTun = Collections.synchronizedList(new ArrayList<>());
        final AtomicLong now = new AtomicLong(EPOCH);
        final PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse("198.18.0.0/15"), now::get);
        final PeerEgressDnsResponder responder;
        final PeerEgressConsumer consumer;

        Harness(PeerEgressDnsResponder.Forwarder forwarder, Executor executor) {
            responder = new PeerEgressDnsResponder(pool, forwarder, executor, toTun::add, now::get);
            closeables.add(responder);
            consumer = new PeerEgressConsumer((egress, frame) -> true, toTun::add);
            consumer.configure(rules(), PeerEgressRules.DEFAULT_MESH_CIDR, VIRTUAL_IP, pool, responder, EPOCH);
        }

        PeerEgressConsumer.Outcome send(byte[] packet) {
            synchronized (consumer) {
                return consumer.handleOutbound(packet, now.get());
            }
        }

        List<byte[]> drain() {
            synchronized (toTun) {
                List<byte[]> copy = new ArrayList<>(toTun);
                toTun.clear();
                return copy;
            }
        }

        List<PeerEgressSegment.Segment> segments() {
            List<PeerEgressSegment.Segment> out = new ArrayList<>();
            for (byte[] packet : drain()) {
                PeerEgressSegment.Segment segment = PeerEgressSegment.parse(packet);
                assertNotNull(segment, "the responder wrote a TCP packet that does not parse or check");
                out.add(segment);
            }
            return out;
        }

        void tick(long advanceMs) {
            now.addAndGet(advanceMs);
            responder.onTick(now.get());
        }
    }

    private static byte[] udpQuery(int source, int destination, int destinationPort, byte[] query) {
        return PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(source, destination, 5353, destinationPort, query));
    }

    private static void waitFor(String what, BooleanSupplier condition) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            try {
                Thread.sleep(2);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                fail("interrupted waiting for " + what);
            }
        }
        fail("timed out waiting for " + what);
    }

    /** The one's-complement sum RFC 1071 checksums are verified with; 0xFFFF means intact. */
    private static int sum(byte[] data, int offset, int length, long initial) {
        long total = initial;
        for (int index = 0; index + 1 < length; index += 2) {
            total += ((data[offset + index] & 0xFF) << 8) | (data[offset + index + 1] & 0xFF);
        }
        if ((length & 1) == 1) {
            total += (data[offset + length - 1] & 0xFF) << 8;
        }
        while ((total >>> 16) != 0) {
            total = (total & 0xFFFF) + (total >>> 16);
        }
        return (int) total;
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int u32(byte[] data, int offset) {
        return (u16(data, offset) << 16) | u16(data, offset + 2);
    }

    // ----------------------------------------------------------------------------------------------
    // UDP through the consumer's read path
    // ----------------------------------------------------------------------------------------------

    /**
     * A query to the listen address is answered, and what reaches the TUN is a well-formed IPv4 UDP
     * packet: from the listen address's port 53 to the port the query came from, header and UDP
     * checksums right, carrying the answer the wire format prescribes.
     */
    @Test
    void answersAQueryWithAWellFormedPacket() {
        Harness harness = new Harness((query, tcp, upstreams) -> null, Runnable::run);
        byte[] query = PeerEgressDnsWireVectorTests.query(0x1234, "www.example.com", PeerEgressDnsMessage.TYPE_A);

        assertEquals(PeerEgressConsumer.Outcome.DNS, harness.send(udpQuery(CLIENT, LISTEN, 53, query)));

        List<byte[]> written = harness.drain();
        assertEquals(1, written.size());
        byte[] packet = written.get(0);
        assertEquals(0x45, packet[0] & 0xFF, "IPv4 with a 20-byte header");
        assertEquals(packet.length, u16(packet, 2), "total length");
        assertEquals(64, packet[8] & 0xFF, "TTL");
        assertEquals(17, packet[9] & 0xFF, "protocol");
        assertEquals(LISTEN, u32(packet, 12), "source");
        assertEquals(CLIENT, u32(packet, 16), "destination");
        assertEquals(0xFFFF, sum(packet, 0, 20, 0), "IPv4 header checksum");
        assertEquals(53, u16(packet, 20), "source port");
        assertEquals(5353, u16(packet, 22), "destination port");
        int udpLength = u16(packet, 24);
        assertEquals(packet.length - 20, udpLength, "UDP length");
        assertTrue(u16(packet, 26) != 0, "no UDP checksum");
        long pseudo = (u16(packet, 12) + u16(packet, 14) + u16(packet, 16) + u16(packet, 18)) + 17L + udpLength;
        assertEquals(0xFFFF, sum(packet, 20, udpLength, pseudo), "UDP checksum");

        PeerEgressFakeIpPool fresh = new PeerEgressFakeIpPool(Ipv4Cidr.parse("198.18.0.0/15"), () -> EPOCH);
        byte[] expected = PeerEgressDnsMessage.respond(rules(), PeerEgressRules.DEFAULT_MESH_CIDR, fresh, query, EPOCH).response();
        assertArrayEquals(expected, Arrays.copyOfRange(packet, 28, packet.length));
        assertTrue(expected.length > 4 && Arrays.equals(Arrays.copyOfRange(expected, expected.length - 4, expected.length),
                new byte[] {(byte) 198, 18, 0, 2}), "not the first fake address");
        assertEquals(1, harness.responder.stats().answered());
    }

    /**
     * Only this machine is answered: its mesh address or one of its interfaces'. Anything else is
     * dropped and counted, and the listen address's other ports are the pool's, which has no mapping
     * for it.
     */
    @Test
    void answersOnlyThisMachine() {
        Harness harness = new Harness((query, tcp, upstreams) -> null, Runnable::run);
        byte[] query = PeerEgressDnsWireVectorTests.query(0x1234, "www.example.com", PeerEgressDnsMessage.TYPE_A);

        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_NOT_LOCAL,
                harness.send(udpQuery(address("10.9.9.9"), LISTEN, 53, query)));
        assertTrue(harness.drain().isEmpty(), "a query from elsewhere was answered");
        assertEquals(1L, harness.consumer.blockedCounts().get("dns-not-local"));

        synchronized (harness.consumer) {
            harness.consumer.setLocalAddresses(candidate -> candidate == address("192.168.1.20"));
        }
        assertEquals(PeerEgressConsumer.Outcome.DNS, harness.send(udpQuery(address("192.168.1.20"), LISTEN, 53, query)));
        assertEquals(1, harness.drain().size());

        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_FAKE_IP, harness.send(udpQuery(CLIENT, LISTEN, 5353, query)));
        assertEquals(PeerEgressConsumer.Outcome.BLOCKED_FAKE_IP, harness.send(PeerEgressSegment.build(
                new PeerEgressSegment.Segment(CLIENT, LISTEN, CLIENT_PORT, 443, 1, 0, PeerEgressSegment.FLAG_SYN,
                        65535, 0, new byte[0]))));
        assertEquals(2L, harness.consumer.blockedCounts().get("fake-ip-unmapped"));
        assertEquals(1, harness.responder.stats().answered());
    }

    // ----------------------------------------------------------------------------------------------
    // Forwarding
    // ----------------------------------------------------------------------------------------------

    /** A UDP upstream on this machine that records what it gets and answers as told. */
    private final class UdpUpstream implements AutoCloseable {
        final DatagramSocket socket;
        final List<byte[]> received = Collections.synchronizedList(new ArrayList<>());
        final Thread thread;

        /** @param replies what to send back for each query, in order; none means stay silent */
        UdpUpstream(java.util.function.Function<byte[], List<byte[]>> replies) throws IOException {
            socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
            closeables.add(this);
            thread = Thread.ofVirtual().start(() -> {
                byte[] buffer = new byte[65_535];
                while (!socket.isClosed()) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    try {
                        socket.receive(packet);
                        byte[] query = Arrays.copyOf(packet.getData(), packet.getLength());
                        received.add(query);
                        for (byte[] reply : replies.apply(query)) {
                            socket.send(new DatagramPacket(reply, reply.length, packet.getSocketAddress()));
                        }
                    } catch (IOException closed) {
                        return;
                    }
                }
            });
        }

        String address() {
            return "127.0.0.1:" + socket.getLocalPort();
        }

        @Override
        public void close() {
            socket.close();
        }
    }

    /** A reply as an upstream would write it: the query's ID, QR set, TC set, some answer bytes. */
    private static byte[] upstreamReply(byte[] query, int id, int size) {
        byte[] reply = new byte[Math.max(size, query.length)];
        System.arraycopy(query, 0, reply, 0, query.length);
        reply[0] = (byte) (id >>> 8);
        reply[1] = (byte) id;
        reply[2] = (byte) 0x83;
        reply[3] = (byte) 0x80;
        for (int index = query.length; index < reply.length; index++) {
            reply[index] = (byte) index;
        }
        return reply;
    }

    private Harness forwardingHarness(long timeoutMs) {
        return new Harness(new PeerEgressDnsForwarder(timeoutMs),
                task -> Thread.ofVirtual().start(task));
    }

    /**
     * Over UDP: the first upstream says nothing and is given its time, the second answers first
     * with a reply of the wrong ID, which is ignored, then with the right one, which comes back
     * byte for byte, TC bit and all. Both upstreams got the query byte for byte.
     */
    @Test
    void forwardsOverUdpToTheFirstUpstreamThatAnswers() throws IOException {
        byte[] query = PeerEgressDnsWireVectorTests.query(0x5151, "example.org", PeerEgressDnsMessage.TYPE_A);
        byte[] right = upstreamReply(query, 0x5151, 300);
        UdpUpstream silent = new UdpUpstream(received -> List.of());
        UdpUpstream answering = new UdpUpstream(received -> List.of(upstreamReply(received, 0x9999, 40), right));
        Harness harness = forwardingHarness(300);
        harness.responder.setUpstreams(List.of(silent.address(), answering.address()));

        assertEquals(PeerEgressConsumer.Outcome.DNS, harness.send(udpQuery(CLIENT, LISTEN, 53, query)));
        waitFor("the relayed reply", () -> !harness.toTun.isEmpty());

        PeerEgressDatagram.Datagram written = PeerEgressDatagram.parse(harness.drain().get(0));
        assertNotNull(written);
        assertArrayEquals(right, written.payload(), "the reply was not relayed as the upstream sent it");
        assertEquals(1, silent.received.size());
        assertArrayEquals(query, silent.received.get(0), "the query was rewritten on its way out");
        assertArrayEquals(query, answering.received.get(0));
        assertEquals(1, harness.responder.stats().forwarded());
    }

    /** Every upstream failing, or none being named, is SERVFAIL built here, counted as failed. */
    @Test
    void answersServfailWhenNoUpstreamAnswers() throws IOException {
        byte[] query = PeerEgressDnsWireVectorTests.query(0x6161, "example.org", PeerEgressDnsMessage.TYPE_A);
        UdpUpstream silent = new UdpUpstream(received -> List.of());
        int closedPort;
        try (DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            closedPort = probe.getLocalPort();
        }
        Harness harness = forwardingHarness(300);
        harness.responder.setUpstreams(List.of(silent.address(), "127.0.0.1:" + closedPort, "not-an-address"));
        assertEquals(List.of(silent.address(), "127.0.0.1:" + closedPort), harness.responder.stats().upstreams());

        harness.send(udpQuery(CLIENT, LISTEN, 53, query));
        waitFor("the SERVFAIL", () -> !harness.toTun.isEmpty());
        assertArrayEquals(PeerEgressDnsMessage.servfail(query),
                PeerEgressDatagram.parse(harness.drain().get(0)).payload());
        assertEquals(1, harness.responder.stats().failed());

        harness.responder.setUpstreams(List.of());
        harness.send(udpQuery(CLIENT, LISTEN, 53, query));
        waitFor("the SERVFAIL without upstreams", () -> !harness.toTun.isEmpty());
        assertEquals(0x8182, u16(PeerEgressDatagram.parse(harness.drain().get(0)).payload(), 2));
        assertEquals(2, harness.responder.stats().failed());
        assertEquals(0, harness.responder.stats().forwarded());
    }

    /**
     * At most 256 forwards are in flight; the next query is not forwarded but answered SERVFAIL at
     * once and counted as failed. The ones in flight still complete.
     */
    @Test
    void refusesToForwardPastTheLimit() {
        CountDownLatch release = new CountDownLatch(1);
        Harness harness = new Harness((query, tcp, upstreams) -> {
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return upstreamReply(query, PeerEgressDnsMessage.id(query), 40);
        }, task -> Thread.ofVirtual().start(task));
        harness.responder.setUpstreams(List.of("192.0.2.53"));
        for (int index = 0; index < PeerEgressDnsResponder.MAX_FORWARDS; index++) {
            harness.send(udpQuery(CLIENT, LISTEN, 53,
                    PeerEgressDnsWireVectorTests.query(index, "example.org", PeerEgressDnsMessage.TYPE_A)));
        }
        assertTrue(harness.drain().isEmpty(), "a forward was answered before its upstream");

        byte[] overflow = PeerEgressDnsWireVectorTests.query(0x7777, "example.org", PeerEgressDnsMessage.TYPE_A);
        harness.send(udpQuery(CLIENT, LISTEN, 53, overflow));
        List<byte[]> written = harness.drain();
        assertEquals(1, written.size(), "the query past the limit was not answered at once");
        assertArrayEquals(PeerEgressDnsMessage.servfail(overflow), PeerEgressDatagram.parse(written.get(0)).payload());
        assertEquals(1, harness.responder.stats().failed());

        release.countDown();
        waitFor("the forwards in flight", () -> harness.responder.stats().forwarded() == PeerEgressDnsResponder.MAX_FORWARDS);
    }

    // ----------------------------------------------------------------------------------------------
    // TCP
    // ----------------------------------------------------------------------------------------------

    private static byte[] segment(int port, int seq, int ack, int flags, byte[] payload, int mss) {
        return PeerEgressSegment.build(new PeerEgressSegment.Segment(CLIENT, LISTEN, port, 53, seq, ack, flags,
                65535, mss, payload));
    }

    private static byte[] framed(byte[]... messages) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] message : messages) {
            out.write(message.length >>> 8);
            out.write(message.length);
            out.writeBytes(message);
        }
        return out.toByteArray();
    }

    /** One connection's client side: its sequence numbers and the server's. */
    private final class Client {
        final Harness harness;
        final int port;
        int seq = 1000;
        int serverSeq;

        Client(Harness harness, int port) {
            this.harness = harness;
            this.port = port;
        }

        /** SYN, SYN-ACK, ACK; returns what the SYN-ACK said. */
        PeerEgressSegment.Segment connect() {
            harness.send(segment(port, seq, 0, PeerEgressSegment.FLAG_SYN, new byte[0], CLIENT_MSS));
            List<PeerEgressSegment.Segment> reply = harness.segments();
            assertEquals(1, reply.size());
            PeerEgressSegment.Segment synAck = reply.get(0);
            assertTrue(synAck.has(PeerEgressSegment.FLAG_SYN) && synAck.has(PeerEgressSegment.FLAG_ACK), "no SYN-ACK");
            seq++;
            serverSeq = synAck.seq() + 1;
            harness.send(segment(port, seq, serverSeq, PeerEgressSegment.FLAG_ACK, new byte[0], 0));
            assertTrue(harness.segments().isEmpty(), "the handshake's ACK was answered");
            return synAck;
        }

        void data(byte[] payload, int extraFlags) {
            harness.send(segment(port, seq, serverSeq, PeerEgressSegment.FLAG_ACK | extraFlags, payload, 0));
            seq += payload.length + ((extraFlags & PeerEgressSegment.FLAG_FIN) != 0 ? 1 : 0);
        }

        void ack(int upTo) {
            serverSeq = upTo;
            harness.send(segment(port, seq, upTo, PeerEgressSegment.FLAG_ACK, new byte[0], 0));
        }

        /** The stream the server sent in these segments, which must follow on from each other. */
        byte[] stream(List<PeerEgressSegment.Segment> segments) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int expected = serverSeq;
            for (PeerEgressSegment.Segment segment : segments) {
                if (segment.payload().length == 0) {
                    continue;
                }
                assertEquals(expected, segment.seq(), "a gap or overlap in the server's stream");
                assertEquals(seq, segment.ack(), "data did not acknowledge what the client sent");
                out.writeBytes(segment.payload());
                expected += segment.payload().length;
            }
            return out.toByteArray();
        }
    }

    /** The handshake, one query answered in one segment, and a query arriving in two pieces. */
    @Test
    void answersAQueryOverTcp() {
        Harness harness = new Harness((query, tcp, upstreams) -> null, Runnable::run);
        Client client = new Client(harness, CLIENT_PORT);
        PeerEgressSegment.Segment synAck = client.connect();
        assertEquals(1001, synAck.ack());
        assertEquals(CLIENT_MSS, synAck.mss(), "the SYN-ACK did not advertise min(peer MSS, 1360)");

        byte[] query = PeerEgressDnsWireVectorTests.query(0x1111, "www.example.com", PeerEgressDnsMessage.TYPE_A);
        client.data(framed(query), PeerEgressSegment.FLAG_PSH);
        List<PeerEgressSegment.Segment> answer = harness.segments();
        assertEquals(1, answer.size());
        byte[] stream = client.stream(answer);
        assertEquals(stream.length - 2, u16(stream, 0), "the answer's length prefix");
        assertEquals(0x1111, u16(stream, 2));
        client.ack(answer.get(0).seq() + answer.get(0).payload().length);

        byte[] second = framed(PeerEgressDnsWireVectorTests.query(0x2222, "api.example.com", PeerEgressDnsMessage.TYPE_A));
        client.data(Arrays.copyOfRange(second, 0, 5), 0);
        List<PeerEgressSegment.Segment> partial = harness.segments();
        assertEquals(1, partial.size(), "half a query was not acknowledged");
        assertEquals(0, partial.get(0).payload().length, "half a query was answered");
        client.data(Arrays.copyOfRange(second, 5, second.length), 0);
        byte[] rest = client.stream(harness.segments());
        assertEquals(0x2222, u16(rest, 2));
        assertEquals(2, harness.responder.stats().answered());
    }

    /**
     * Two queries in one segment, the first forwarded and the second answered here: nothing is
     * written until the forward comes back, then both, in the order they were asked.
     */
    @Test
    void answersPipelinedQueriesInArrivalOrder() {
        Deferred upstream = new Deferred();
        byte[] forwardedQuery = PeerEgressDnsWireVectorTests.query(0x0A0A, "example.org", PeerEgressDnsMessage.TYPE_A);
        byte[] forwardedReply = upstreamReply(forwardedQuery, 0x0A0A, 120);
        Harness harness = new Harness((query, tcp, upstreams) -> {
            assertTrue(tcp, "a TCP query was forwarded over UDP");
            return forwardedReply;
        }, upstream);
        harness.responder.setUpstreams(List.of("192.0.2.53"));
        Client client = new Client(harness, CLIENT_PORT);
        client.connect();

        byte[] local = PeerEgressDnsWireVectorTests.query(0x0B0B, "www.example.com", PeerEgressDnsMessage.TYPE_A);
        client.data(framed(forwardedQuery, local), PeerEgressSegment.FLAG_PSH);
        List<PeerEgressSegment.Segment> waiting = harness.segments();
        assertEquals(1, waiting.size());
        assertEquals(0, waiting.get(0).payload().length, "the local answer overtook the forwarded one");

        upstream.runAll();
        byte[] stream = client.stream(harness.segments());
        assertEquals(forwardedReply.length, u16(stream, 0));
        assertArrayEquals(forwardedReply, Arrays.copyOfRange(stream, 2, 2 + forwardedReply.length));
        int second = 2 + forwardedReply.length;
        assertEquals(0x0B0B, u16(stream, second + 2), "the second answer is not the second query's");
        assertEquals(stream.length, second + 2 + u16(stream, second));
        assertEquals(1, harness.responder.stats().forwarded());
        assertEquals(1, harness.responder.stats().answered());
    }

    /** A large forwarded reply goes out in segments of the negotiated MSS, in order. */
    @Test
    void splitsALargeReplyByMss() {
        byte[] query = PeerEgressDnsWireVectorTests.query(0x0C0C, "example.org", 16);
        byte[] big = upstreamReply(query, 0x0C0C, 3000);
        Harness harness = new Harness((asked, tcp, upstreams) -> big, Runnable::run);
        harness.responder.setUpstreams(List.of("192.0.2.53"));
        Client client = new Client(harness, CLIENT_PORT);
        client.connect();

        client.data(framed(query), PeerEgressSegment.FLAG_PSH);
        List<PeerEgressSegment.Segment> segments = harness.segments();
        List<Integer> sizes = segments.stream().map(segment -> segment.payload().length).toList();
        assertEquals(List.of(1000, 1000, 1000, 2), sizes);
        byte[] stream = client.stream(segments);
        assertArrayEquals(big, Arrays.copyOfRange(stream, 2, stream.length));
    }

    /**
     * An answer that is not acknowledged is sent again after a second, three times; then the
     * connection is reset and forgotten. An acknowledgement stops it.
     */
    @Test
    void retransmitsThreeTimesThenResets() {
        Harness harness = new Harness((query, tcp, upstreams) -> null, Runnable::run);
        Client client = new Client(harness, CLIENT_PORT);
        client.connect();
        client.data(framed(PeerEgressDnsWireVectorTests.query(1, "www.example.com", PeerEgressDnsMessage.TYPE_A)), 0);
        PeerEgressSegment.Segment first = harness.segments().get(0);

        harness.tick(999);
        assertTrue(harness.segments().isEmpty(), "sent again before a second");
        for (int attempt = 1; attempt <= PeerEgressDnsResponder.MAX_RETRANSMITS; attempt++) {
            harness.tick(1);
            List<PeerEgressSegment.Segment> again = harness.segments();
            assertEquals(1, again.size(), "attempt " + attempt);
            assertEquals(first.seq(), again.get(0).seq());
            assertArrayEquals(first.payload(), again.get(0).payload());
            harness.tick(999);
        }
        harness.tick(1);
        List<PeerEgressSegment.Segment> reset = harness.segments();
        assertEquals(1, reset.size());
        assertTrue(reset.get(0).has(PeerEgressSegment.FLAG_RST), "not reset after three retransmissions");
        assertEquals(0, harness.responder.connectionCount());

        Client patient = new Client(harness, CLIENT_PORT + 1);
        patient.connect();
        patient.data(framed(PeerEgressDnsWireVectorTests.query(2, "www.example.com", PeerEgressDnsMessage.TYPE_A)), 0);
        PeerEgressSegment.Segment answer = harness.segments().get(0);
        harness.tick(1000);
        assertEquals(1, harness.segments().size());
        patient.ack(answer.seq() + answer.payload().length);
        harness.tick(5000);
        assertTrue(harness.segments().isEmpty(), "sent again after it was acknowledged");
    }

    /** A SYN-ACK nobody acknowledges is sent three more times, then the half-open connection is reset. */
    @Test
    void givesUpOnAHandshakeThatIsNotCompleted() {
        Harness harness = new Harness((query, tcp, upstreams) -> null, Runnable::run);
        harness.send(segment(CLIENT_PORT, 5000, 0, PeerEgressSegment.FLAG_SYN, new byte[0], 1460));
        PeerEgressSegment.Segment synAck = harness.segments().get(0);
        assertEquals(PeerEgressDnsResponder.TCP_MSS, synAck.mss(), "the SYN-ACK did not cap the MSS at 1360");
        harness.send(segment(CLIENT_PORT, 5000, 0, PeerEgressSegment.FLAG_SYN, new byte[0], 1460));
        assertEquals(synAck.seq(), harness.segments().get(0).seq(), "a retransmitted SYN opened a second connection");
        for (int attempt = 0; attempt < PeerEgressDnsResponder.MAX_RETRANSMITS; attempt++) {
            harness.tick(PeerEgressDnsResponder.RETRANSMIT_MS);
            assertTrue(harness.segments().get(0).has(PeerEgressSegment.FLAG_SYN));
        }
        harness.tick(PeerEgressDnsResponder.RETRANSMIT_MS);
        assertTrue(harness.segments().get(0).has(PeerEgressSegment.FLAG_RST));
        assertEquals(0, harness.responder.connectionCount());
    }

    /**
     * The client's FIN is answered with a FIN only once the answers owed are written, a forwarded
     * one included; the connection is gone when the FIN is acknowledged.
     */
    @Test
    void closesAfterWritingWhatIsOwed() {
        Deferred upstream = new Deferred();
        byte[] query = PeerEgressDnsWireVectorTests.query(0x0D0D, "example.org", PeerEgressDnsMessage.TYPE_A);
        Harness harness = new Harness((asked, tcp, upstreams) -> upstreamReply(asked, 0x0D0D, 60), upstream);
        harness.responder.setUpstreams(List.of("192.0.2.53"));
        Client client = new Client(harness, CLIENT_PORT);
        client.connect();

        client.data(framed(query), PeerEgressSegment.FLAG_FIN);
        List<PeerEgressSegment.Segment> early = harness.segments();
        assertEquals(1, early.size());
        assertFalse(early.get(0).has(PeerEgressSegment.FLAG_FIN), "FIN before the owed answer");
        assertEquals(client.seq, early.get(0).ack(), "the client's FIN was not acknowledged");

        upstream.runAll();
        List<PeerEgressSegment.Segment> closing = harness.segments();
        PeerEgressSegment.Segment last = closing.get(closing.size() - 1);
        assertTrue(last.has(PeerEgressSegment.FLAG_FIN), "no FIN after the answer");
        assertTrue(closing.get(0).payload().length > 0, "the answer did not come first");
        client.ack(last.seq() + 1);
        assertEquals(0, harness.responder.connectionCount(), "the connection outlived both FINs");
    }

    /** Ten seconds without a query and with none unanswered: this side sends FIN. */
    @Test
    void closesAnIdleConnection() {
        Harness harness = new Harness((query, tcp, upstreams) -> null, Runnable::run);
        Client client = new Client(harness, CLIENT_PORT);
        client.connect();

        harness.tick(PeerEgressDnsResponder.IDLE_MS - 1);
        assertTrue(harness.segments().isEmpty(), "closed before ten idle seconds");
        harness.tick(1);
        List<PeerEgressSegment.Segment> fin = harness.segments();
        assertEquals(1, fin.size());
        assertTrue(fin.get(0).has(PeerEgressSegment.FLAG_FIN));
        client.ack(fin.get(0).seq() + 1);
        client.data(new byte[0], PeerEgressSegment.FLAG_FIN);
        List<PeerEgressSegment.Segment> last = harness.segments();
        assertEquals(1, last.size());
        assertEquals(client.seq, last.get(0).ack(), "the client's FIN was not acknowledged");
        assertEquals(0, harness.responder.connectionCount());
    }

    /**
     * At most 64 connections; a SYN beyond is reset, a segment for no connection is reset, an
     * out-of-order one is dropped with the current ACK sent again, and a RST drops the connection.
     */
    @Test
    void keepsToItsLimitsAndDropsWhatIsOutOfOrder() {
        Harness harness = new Harness((query, tcp, upstreams) -> null, Runnable::run);
        for (int index = 0; index < PeerEgressDnsResponder.MAX_TCP_CONNECTIONS; index++) {
            harness.send(segment(30_000 + index, 7, 0, PeerEgressSegment.FLAG_SYN, new byte[0], 1000));
        }
        assertEquals(PeerEgressDnsResponder.MAX_TCP_CONNECTIONS, harness.segments().size());
        harness.send(segment(31_000, 7, 0, PeerEgressSegment.FLAG_SYN, new byte[0], 1000));
        PeerEgressSegment.Segment refused = harness.segments().get(0);
        assertTrue(refused.has(PeerEgressSegment.FLAG_RST) && refused.has(PeerEgressSegment.FLAG_ACK));
        assertEquals(8, refused.ack());
        assertEquals(PeerEgressDnsResponder.MAX_TCP_CONNECTIONS, harness.responder.connectionCount());

        harness.send(segment(32_000, 9, 1234, PeerEgressSegment.FLAG_ACK, new byte[0], 0));
        PeerEgressSegment.Segment stray = harness.segments().get(0);
        assertTrue(stray.has(PeerEgressSegment.FLAG_RST));
        assertEquals(1234, stray.seq(), "a reset for an ACK takes its sequence from that ACK");

        Harness fresh = new Harness((query, tcp, upstreams) -> null, Runnable::run);
        Client client = new Client(fresh, CLIENT_PORT);
        client.connect();
        byte[] query = framed(PeerEgressDnsWireVectorTests.query(3, "www.example.com", PeerEgressDnsMessage.TYPE_A));
        fresh.send(segment(CLIENT_PORT, client.seq + 5, client.serverSeq, PeerEgressSegment.FLAG_ACK, query, 0));
        List<PeerEgressSegment.Segment> duplicate = fresh.segments();
        assertEquals(1, duplicate.size());
        assertEquals(0, duplicate.get(0).payload().length, "an out-of-order query was answered");
        assertEquals(client.seq, duplicate.get(0).ack(), "the current ACK was not sent again");

        fresh.send(segment(CLIENT_PORT, client.seq, client.serverSeq, PeerEgressSegment.FLAG_RST, new byte[0], 0));
        assertTrue(fresh.segments().isEmpty(), "a RST was answered");
        assertEquals(0, fresh.responder.connectionCount());
    }

    /**
     * Over TCP to real upstreams on this machine: one that accepts and never answers is given its
     * two seconds (shortened here), one that refuses is passed over, and the one that answers has
     * its reply relayed whole, split by the MSS.
     */
    @Test
    void forwardsOverTcpToTheFirstUpstreamThatAnswers() throws Exception {
        byte[] query = PeerEgressDnsWireVectorTests.query(0x0E0E, "example.org", 16);
        byte[] big = upstreamReply(query, 0x0E0E, 2500);
        ServerSocket silent = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        closeables.add(silent);
        List<Socket> held = Collections.synchronizedList(new ArrayList<>());
        Thread.ofVirtual().start(() -> {
            try {
                while (true) {
                    held.add(silent.accept());
                }
            } catch (IOException closed) {
                // The test is over.
            }
        });
        int refusedPort;
        try (ServerSocket probe = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            refusedPort = probe.getLocalPort();
        }
        ServerSocket answering = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        closeables.add(answering);
        List<byte[]> received = Collections.synchronizedList(new ArrayList<>());
        Thread.ofVirtual().start(() -> {
            try (Socket socket = answering.accept()) {
                DataInputStream in = new DataInputStream(socket.getInputStream());
                byte[] asked = new byte[in.readUnsignedShort()];
                in.readFully(asked);
                received.add(asked);
                OutputStream out = socket.getOutputStream();
                out.write(framed(big));
                out.flush();
            } catch (IOException closed) {
                // The test is over.
            }
        });

        Harness harness = forwardingHarness(300);
        harness.responder.setUpstreams(List.of("127.0.0.1:" + silent.getLocalPort(), "127.0.0.1:" + refusedPort,
                "127.0.0.1:" + answering.getLocalPort()));
        Client client = new Client(harness, CLIENT_PORT);
        client.connect();
        client.data(framed(query), PeerEgressSegment.FLAG_PSH);
        harness.segments();

        List<PeerEgressSegment.Segment> segments = new ArrayList<>();
        waitFor("the relayed reply", () -> {
            segments.addAll(harness.segments());
            return segments.stream().mapToInt(segment -> segment.payload().length).sum() >= big.length + 2;
        });
        byte[] stream = client.stream(segments);
        assertArrayEquals(big, Arrays.copyOfRange(stream, 2, stream.length));
        assertTrue(segments.stream().allMatch(segment -> segment.payload().length <= CLIENT_MSS));
        assertArrayEquals(query, received.get(0), "the query was rewritten on its way out");
        assertEquals(1, held.size(), "the silent upstream was not tried first");
        assertEquals(1, harness.responder.stats().forwarded());
        for (Socket socket : held) {
            socket.close();
        }
    }

    @Test
    void readsUpstreamsAsLiteralAddresses() {
        assertEquals(53, PeerEgressDnsForwarder.parseUpstream("192.0.2.53").getPort());
        assertEquals(5353, PeerEgressDnsForwarder.parseUpstream(" 127.0.0.1:5353 ").getPort());
        assertEquals(53, PeerEgressDnsForwarder.parseUpstream("2001:db8::53").getPort());
        assertEquals(853, PeerEgressDnsForwarder.parseUpstream("[2001:db8::53]:853").getPort());
        for (String bad : List.of("", "dns.example", "192.0.2.53:0", "192.0.2.53:70000", "010.0.0.1", "[::1]x")) {
            assertEquals(null, PeerEgressDnsForwarder.parseUpstream(bad), bad);
        }
        assertEquals(2_000L, PeerEgressDnsForwarder.UPSTREAM_TIMEOUT_MS);
    }
}
