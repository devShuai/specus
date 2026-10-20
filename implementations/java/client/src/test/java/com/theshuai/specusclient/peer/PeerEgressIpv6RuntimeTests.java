package com.theshuai.specusclient.peer;

import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.CONSUMER_MESH;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.EPOCH;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.address4;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.address6;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.consumer6;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.frameFor;
import static com.theshuai.specusclient.peer.PeerEgressIpv6Harness.syn6;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The egress runtime carrying IPv6 ({@code protocol/spec/peer-egress.md}, IPv6 数据面, 出口),
 * mirroring the IPv4 suites: real bytes over real sockets, and the refusals that keep a consumer to
 * its own address and out of the mesh.
 */
class PeerEgressIpv6RuntimeTests {

    private static final HexFormat HEX = HexFormat.of();

    /**
     * Holds a returned packet to what the spec fixes: version 6, traffic class and flow label zero,
     * hop limit 64, from the target to the consumer's derived address.
     */
    private static void checkReturnHeader(byte[] packet, PeerEgressIpv6Packet.Address source,
            PeerEgressIpv6Packet.Address destination) {
        assertEquals("60000000", HEX.formatHex(packet, 0, 4), "version, traffic class and flow label");
        assertEquals(PeerEgressIpv6Packet.HOP_LIMIT, packet[7] & 0xFF, "hop limit");
        assertEquals(source, PeerEgressIpv6Packet.Address.read(packet, 8), "source");
        assertEquals(destination, PeerEgressIpv6Packet.Address.read(packet, 24), "destination");
    }

    /** The IPv6 loopback, or the test is skipped: a host without it cannot run the real-socket half. */
    private static InetAddress loopback6() {
        try {
            InetAddress loopback = InetAddress.getByName("::1");
            try (ServerSocket probe = new ServerSocket()) {
                probe.bind(new InetSocketAddress(loopback, 0));
            }
            return loopback;
        } catch (IOException unavailable) {
            Assumptions.abort("no IPv6 loopback on this host (" + unavailable + "); the IPv6 real-socket tests need ::1");
            return null;
        }
    }

    /**
     * A consumer speaking IPv6 to a runtime whose dialer reaches target on ::1, while the consumer
     * and the policy both speak the routable destination: ::1 is on the forced-deny list, so naming
     * it would only ever prove the refusal.
     */
    private static final class Consumer6 {
        final PeerEgressRuntime runtime;
        final PeerEgressIpv6Packet.Address local = consumer6();
        final PeerEgressIpv6Packet.Address remote;
        final int port = 40000;
        final int target = 443;
        int seq = 1000;
        int ack;
        final List<byte[]> packets = new ArrayList<>();
        final List<PeerEgressSegment.Segment> inbound = new ArrayList<>();
        final List<PeerEgressDatagram.Datagram> datagrams = new ArrayList<>();
        final StringBuilder received = new StringBuilder();

        Consumer6(InetSocketAddress real, String destination) {
            remote = address6(destination);
            PeerEgressSocketDialer dialer = new PeerEgressSocketDialer(PeerEgressSocketBinder.none());
            runtime = new PeerEgressRuntime(
                    (consumer, frame) -> onFrame(frame.clone()),
                    (protocol, host, port, timeoutMs) ->
                            dialer.dial(protocol, real.getAddress().getHostAddress(), real.getPort(), timeoutMs));
            runtime.applyPolicy(PeerEgressIpv6Harness.policy(PeerEgressPolicy.SCOPE_PUBLIC, destination + "/128"),
                    PeerEgressAuthorization.Context.defaults(), System.currentTimeMillis());
        }

        private synchronized void onFrame(byte[] raw) {
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw, true);
            assertTrue(frame.accepted(), "the egress sent a frame that does not parse: " + frame.code());
            if (frame.type() != PeerEgressFrame.TYPE_IP_PACKET) {
                return;
            }
            packets.add(frame.body());
            PeerEgressDatagram.Datagram datagram = PeerEgressIpv6Packet.parseDatagram(frame.body());
            if (datagram != null) {
                datagrams.add(datagram);
                return;
            }
            PeerEgressSegment.Segment segment = PeerEgressIpv6Packet.parseSegment(frame.body());
            assertNotNull(segment, "the egress sent an IPv6 packet that is neither TCP nor UDP");
            inbound.add(segment);
            if (segment.payload().length > 0) {
                received.append(new String(segment.payload(), StandardCharsets.US_ASCII));
                ack = segment.seq() + segment.payload().length;
            }
        }

        void send(int flags, byte[] payload) {
            PeerEgressSegment.Segment segment;
            synchronized (this) {
                segment = new PeerEgressSegment.Segment(0, 0, port, target, seq, ack, flags, 65535,
                        (flags & PeerEgressSegment.FLAG_SYN) != 0 ? 1360 : 0, payload, local, remote);
                seq += segment.segmentLength();
            }
            runtime.handleFrame(7, CONSUMER_MESH, frameFor(PeerEgressSegment.build(segment)),
                    System.currentTimeMillis());
        }

        synchronized List<byte[]> packets() {
            return List.copyOf(packets);
        }
    }

    /**
     * A handshake, a request and its echo, through the user-space stack to a real listener on ::1,
     * with the headers of everything returned checked.
     */
    @Test
    void carriesTcpEndToEnd() throws Exception {
        InetAddress loopback = loopback6();
        try (ServerSocket listener = new ServerSocket()) {
            listener.bind(new InetSocketAddress(loopback, 0));
            Thread server = Thread.ofVirtual().start(() -> {
                try (Socket socket = listener.accept()) {
                    byte[] buffer = new byte[64];
                    int read = socket.getInputStream().read(buffer);
                    socket.getOutputStream().write(("echo:" + new String(buffer, 0, read, StandardCharsets.US_ASCII))
                            .getBytes(StandardCharsets.US_ASCII));
                    socket.getOutputStream().flush();
                } catch (IOException ignored) {
                    // The assertions below report what did not arrive.
                }
            });
            Consumer6 consumer = new Consumer6((InetSocketAddress) listener.getLocalSocketAddress(), "2001:db8:1::c8");
            try {
                consumer.send(PeerEgressSegment.FLAG_SYN, new byte[0]);
                PeerEgressSegment.Segment[] synAck = new PeerEgressSegment.Segment[1];
                PeerEgressIpv6Harness.waitFor("the SYN-ACK", () -> {
                    synchronized (consumer) {
                        for (PeerEgressSegment.Segment segment : consumer.inbound) {
                            if (segment.has(PeerEgressSegment.FLAG_SYN) && segment.has(PeerEgressSegment.FLAG_ACK)) {
                                synAck[0] = segment;
                                consumer.ack = segment.seq() + 1;
                                return true;
                            }
                        }
                        return false;
                    }
                });
                // The path MTU the stack starts from is 1280; an IPv6 header and a TCP header come out of it.
                assertEquals(PeerEgressRuntime.DEFAULT_PATH_MTU - PeerEgressIpv6Packet.HEADER_BYTES
                        - PeerEgressSegment.TCP_MIN_HEADER_BYTES, synAck[0].mss(), "SYN-ACK MSS");
                consumer.send(PeerEgressSegment.FLAG_ACK, new byte[0]);
                consumer.send(PeerEgressSegment.FLAG_ACK | PeerEgressSegment.FLAG_PSH,
                        "hello".getBytes(StandardCharsets.US_ASCII));
                PeerEgressIpv6Harness.waitFor("the echoed reply", () -> {
                    synchronized (consumer) {
                        return consumer.received.toString().equals("echo:hello");
                    }
                });
                server.join(5000);
                for (byte[] packet : consumer.packets()) {
                    checkReturnHeader(packet, consumer.remote, consumer.local);
                }
            } finally {
                consumer.runtime.shutdown(System.currentTimeMillis());
            }
        }
    }

    /** A datagram out and its answer back, over a real UDP socket on ::1. */
    @Test
    void carriesUdpEndToEnd() throws Exception {
        InetAddress loopback = loopback6();
        try (DatagramSocket listener = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
            Thread.ofVirtual().start(() -> {
                try {
                    byte[] buffer = new byte[64];
                    DatagramPacket query = new DatagramPacket(buffer, buffer.length);
                    listener.receive(query);
                    byte[] answer = ("answer:" + new String(buffer, 0, query.getLength(), StandardCharsets.US_ASCII))
                            .getBytes(StandardCharsets.US_ASCII);
                    listener.send(new DatagramPacket(answer, answer.length, query.getSocketAddress()));
                } catch (IOException ignored) {
                    // The assertions below report what did not arrive.
                }
            });
            Consumer6 consumer = new Consumer6((InetSocketAddress) listener.getLocalSocketAddress(), "2001:db8:1::35");
            try {
                PeerEgressDatagram.Datagram query = new PeerEgressDatagram.Datagram(0, 0, 51000, 53,
                        "query".getBytes(StandardCharsets.US_ASCII), consumer.local, consumer.remote);
                consumer.runtime.handleFrame(7, CONSUMER_MESH, frameFor(PeerEgressDatagram.build(query)),
                        System.currentTimeMillis());
                PeerEgressIpv6Harness.waitFor("the answer", () -> {
                    synchronized (consumer) {
                        return !consumer.datagrams.isEmpty();
                    }
                });
                PeerEgressDatagram.Datagram reply;
                synchronized (consumer) {
                    reply = consumer.datagrams.get(0);
                }
                assertEquals("answer:query", new String(reply.payload(), StandardCharsets.US_ASCII));
                assertEquals(query.destinationIp6(), reply.sourceIp6(), "the reply did not mirror the flow");
                assertEquals(query.sourceIp6(), reply.destinationIp6(), "the reply did not mirror the flow");
                assertEquals(53, reply.sourcePort());
                assertEquals(51000, reply.destinationPort());
                checkReturnHeader(consumer.packets().get(0), consumer.remote, consumer.local);
            } finally {
                consumer.runtime.shutdown(System.currentTimeMillis());
            }
        }
    }

    /**
     * A consumer speaks only for its own derived address. A packet from any other source -- another
     * device's derived address, an address outside the prefix -- is dropped before anything is
     * judged, opened or answered, and so is every IPv6 packet from a session whose mesh address is
     * unknown.
     */
    @Test
    void dropsAForgedSource() {
        PeerEgressIpv6Packet.Address another = PeerEgressIpv6Packet.meshAddress(address4("100.96.0.2"));
        List<BiConsumer<PeerEgressIpv6Harness, PeerEgressSegment.Segment>> forgeries = List.of(
                // Another device's derived address.
                (harness, syn) -> harness.runtime.handleFrame(7, CONSUMER_MESH,
                        frameFor(PeerEgressSegment.build(withSource(syn, another))), EPOCH),
                // An address outside the prefix.
                (harness, syn) -> harness.runtime.handleFrame(7, CONSUMER_MESH,
                        frameFor(PeerEgressSegment.build(withSource(syn, address6("2001:db8:ffff::1")))), EPOCH),
                // A session without a mesh address.
                (harness, syn) -> harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(syn)), EPOCH),
                // A datagram from another device's session, carrying this consumer's address.
                (harness, syn) -> harness.runtime.handleFrame(9, "100.96.0.9",
                        frameFor(PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(0, 0, 51000, 53,
                                "query".getBytes(StandardCharsets.US_ASCII), syn.sourceIp6(), syn.destinationIp6()))),
                        EPOCH));
        for (int index = 0; index < forgeries.size(); index++) {
            PeerEgressIpv6Harness harness = new PeerEgressIpv6Harness("::/0");
            forgeries.get(index).accept(harness, syn6(40000, "2001:db8:1::c8", 443));
            assertEquals(0, harness.dialCount(), "forgery " + index + " opened a flow");
            assertEquals(0, harness.runtime.flowCount(), "forgery " + index + " opened a flow");
            assertEquals(0, harness.frameCount(), "forgery " + index + " was answered");
            assertTrue(harness.runtime.rejections().cumulativeCounts().isEmpty(),
                    "forgery " + index + " was counted: " + harness.runtime.rejections().cumulativeCounts());
        }
        // And the same SYN from the right address opens, so the drop above is the source and nothing else.
        PeerEgressIpv6Harness harness = new PeerEgressIpv6Harness("::/0");
        harness.runtime.handleFrame(7, CONSUMER_MESH, frameFor(PeerEgressSegment.build(syn6(40000, "2001:db8:1::c8", 443))),
                EPOCH);
        assertEquals(List.of("2001:db8:1::c8 443"), harness.dialed(), "the consumer's own address");
        harness.runtime.shutdown(EPOCH);
    }

    private static PeerEgressSegment.Segment withSource(PeerEgressSegment.Segment segment,
            PeerEgressIpv6Packet.Address source) {
        return new PeerEgressSegment.Segment(0, 0, segment.sourcePort(), segment.destinationPort(), segment.seq(),
                segment.ack(), segment.flags(), segment.window(), segment.mss(), segment.payload(),
                source, segment.destinationIp6());
    }

    /**
     * The derived prefix is the mesh to IPv6: a destination inside it is refused the way a mesh IPv4
     * destination is, however broad the policy, and the consumer gets an IPv6 reset and a
     * flow-reject written in IPv6.
     */
    @Test
    void refusesAMeshDestination() {
        PeerEgressIpv6Harness harness = new PeerEgressIpv6Harness();
        harness.runtime.applyPolicy(PeerEgressIpv6Harness.policy(PeerEgressPolicy.SCOPE_LAN, "::/0", "fc00::/7"),
                PeerEgressAuthorization.Context.defaults(), EPOCH);
        String destination = "fd53:7065:6375:7300::6460:2";
        harness.runtime.handleFrame(7, CONSUMER_MESH, frameFor(PeerEgressSegment.build(syn6(40000, destination, 22))),
                EPOCH);

        assertEquals(0, harness.dialCount(), "a mesh destination was dialled");
        List<PeerEgressFrame.Control> controls = harness.controls();
        assertEquals(1, controls.size(), "flow-rejects: " + controls);
        PeerEgressFrame.Control reject = controls.get(0);
        assertEquals(PeerEgressCodes.FORBIDDEN_DESTINATION, reject.code());
        assertEquals("tcp", reject.protocol());
        assertEquals("fd53:7065:6375:7300::6460:1", reject.sourceIp());
        assertEquals(40000, reject.sourcePort());
        assertEquals(destination, reject.destinationIp());
        assertEquals(22, reject.destinationPort());
        List<PeerEgressSegment.Segment> segments = harness.segments6();
        assertEquals(1, segments.size(), "segments: " + segments);
        assertTrue(segments.get(0).has(PeerEgressSegment.FLAG_RST), "the consumer was not reset");
        checkReturnHeader(harness.packets6().get(0), address6(destination), consumer6());

        // The same policy reaches an address next to the prefix, so the refusal is the prefix.
        harness.runtime.handleFrame(7, CONSUMER_MESH,
                frameFor(PeerEgressSegment.build(syn6(40001, "fd53:7065:6375:7301::1", 22))), EPOCH);
        assertEquals(List.of("fd53:7065:6375:7301::1 22"), harness.dialed());
        harness.runtime.shutdown(EPOCH);
    }

    /** ICMPv6 is refused the way ICMP over IPv4 is, before the source or anything else is looked at. */
    @Test
    void refusesIcmpv6() {
        PeerEgressIpv6Harness harness = new PeerEgressIpv6Harness("::/0");
        byte[] packet = new byte[PeerEgressIpv6Packet.HEADER_BYTES + 8];
        PeerEgressIpv6Packet.writeHeader(packet, PeerEgressIpv6Packet.NEXT_HEADER_ICMP, 8,
                consumer6(), address6("2001:db8:1::c8"));
        packet[PeerEgressIpv6Packet.HEADER_BYTES] = (byte) 128; // echo request
        harness.runtime.handleFrame(7, CONSUMER_MESH, frameFor(packet), EPOCH);

        assertEquals(0, harness.dialCount(), "ICMPv6 opened a socket");
        assertEquals(List.of(PeerEgressCodes.PROTOCOL_DENIED), harness.rejectCodes());
        assertEquals("::", harness.controls().get(0).sourceIp(), "the refusal names no address it was not given");
    }

    /** A stray segment for an IPv6 flow that was never opened gets an IPv6 reset at the stray's ACK. */
    @Test
    void resetsSegmentsForUnknownFlows() {
        PeerEgressIpv6Harness harness = new PeerEgressIpv6Harness("::/0");
        PeerEgressSegment.Segment stray = new PeerEgressSegment.Segment(0, 0, 40000, 443, 5000, 9000,
                PeerEgressSegment.FLAG_ACK, 65535, 0, "stale".getBytes(StandardCharsets.US_ASCII),
                consumer6(), address6("2001:db8:1::c8"));
        harness.runtime.handleFrame(7, CONSUMER_MESH, frameFor(PeerEgressSegment.build(stray)), EPOCH);

        assertEquals(0, harness.dialCount(), "a stray segment opened a socket");
        List<PeerEgressSegment.Segment> segments = harness.segments6();
        assertEquals(1, segments.size());
        assertTrue(segments.get(0).has(PeerEgressSegment.FLAG_RST));
        assertEquals(9000, segments.get(0).seq());
        checkReturnHeader(harness.packets6().get(0), address6("2001:db8:1::c8"), consumer6());
    }

    /**
     * flow-purge names IPv6 prefixes as well, and a prefix closes only flows of its own family. A
     * policy push that withdraws the IPv6 rule closes the IPv6 flow with a flow-reject written in IPv6.
     */
    @Test
    void flowsArePurgedAndRevokedByFamily() {
        PeerEgressIpv6Harness harness = new PeerEgressIpv6Harness("203.0.113.0/24", "2001:db8:1::/48");
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address4(CONSUMER_MESH), address4("203.0.113.10"), 40000, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]))), EPOCH);
        harness.runtime.handleFrame(7, CONSUMER_MESH,
                frameFor(PeerEgressSegment.build(syn6(40001, "2001:db8:1::c8", 443))), EPOCH);
        PeerEgressIpv6Harness.waitFor("both flows to open", () -> harness.runtime.flowCount() == 2);

        // 0.0.0.0/0 holds no IPv6 flow, and an IPv6 prefix that misses leaves it too.
        purge(harness, List.of("0.0.0.0/0", "2001:db8:2::/48"));
        assertEquals(1, harness.runtime.flowCount(), "an IPv4 purge reached the IPv6 flow or missed the IPv4 one");
        assertTrue(harness.socket(0).isClosed(), "the IPv4 flow is still open");
        assertFalse(harness.socket(1).isClosed(), "the IPv6 flow was closed");
        // ::/0 holds no IPv4 flow either.
        harness.runtime.handleFrame(7, frameFor(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                address4(CONSUMER_MESH), address4("203.0.113.11"), 40002, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]))), EPOCH);
        PeerEgressIpv6Harness.waitFor("the second IPv4 flow to open", () -> harness.runtime.flowCount() == 2);
        purge(harness, List.of("2001:db8:2::/48"));
        assertEquals(2, harness.runtime.flowCount(), "a purge of nothing closed something");

        harness.runtime.applyPolicy(PeerEgressIpv6Harness.policy(PeerEgressPolicy.SCOPE_PUBLIC, "203.0.113.0/24"),
                PeerEgressAuthorization.Context.defaults(), EPOCH);
        assertEquals(1, harness.runtime.flowCount(), "withdrawing the IPv6 rule left the IPv6 flow open");
        assertTrue(harness.socket(1).isClosed(), "the IPv6 flow's socket is still open");
        PeerEgressFrame.Control revoked = null;
        for (PeerEgressFrame.Control control : harness.controls()) {
            if (PeerEgressCodes.DEST_DENIED.equals(control.code())) {
                revoked = control;
            }
        }
        assertNotNull(revoked, "no revocation flow-reject");
        assertEquals("fd53:7065:6375:7300::6460:1", revoked.sourceIp());
        assertEquals(40001, revoked.sourcePort());
        assertEquals("2001:db8:1::c8", revoked.destinationIp());

        // An IPv6 purge reaches an IPv6 flow, and only it.
        harness.runtime.applyPolicy(PeerEgressIpv6Harness.policy(PeerEgressPolicy.SCOPE_PUBLIC,
                        "203.0.113.0/24", "2001:db8:1::/48"),
                PeerEgressAuthorization.Context.defaults(), EPOCH);
        harness.runtime.handleFrame(7, CONSUMER_MESH,
                frameFor(PeerEgressSegment.build(syn6(40003, "2001:db8:1::c9", 443))), EPOCH);
        PeerEgressIpv6Harness.waitFor("the IPv6 flow to open", () -> harness.runtime.flowCount() == 2);
        purge(harness, List.of("2001:db8:1::c9"));
        assertEquals(1, harness.runtime.flowCount(), "an IPv6 purge left its flow open, or closed the IPv4 one");
        assertTrue(harness.runtime.hasFlow(new PeerEgressFlowTable.Key(PeerEgressSegment.IPV4_PROTOCOL_TCP,
                address4(CONSUMER_MESH), 40002, address4("203.0.113.11"), 443)), "the IPv4 flow went with it");
        harness.runtime.shutdown(EPOCH);
    }

    private static void purge(PeerEgressIpv6Harness harness, List<String> destinations) {
        harness.runtime.handleFrame(7, PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false,
                PeerEgressFrame.encodeControl(PeerEgressFrame.Control.flowPurge(destinations, null))), EPOCH);
    }

    /**
     * Names are bound to IPv4 fake addresses only: an IPv6 flow is dialled to its own address and
     * no name-bind closes it. 0.0.0.0 is what an IPv6 key holds in its IPv4 fields, so a binding of
     * it is what a key that confused the families would find.
     */
    @Test
    void namesNeverReachIpv6Flows() {
        PeerEgressIpv6Harness harness = new PeerEgressIpv6Harness("::/0", "203.0.113.0/24");
        harness.runtime.resolve = name -> List.of("203.0.113.5");
        bindName(harness, "0.0.0.0", "example.com");
        harness.runtime.handleFrame(7, CONSUMER_MESH,
                frameFor(PeerEgressSegment.build(syn6(40000, "2001:db8:1::c8", 443))), EPOCH);
        PeerEgressIpv6Harness.waitFor("the flow to open", () -> harness.runtime.flowCount() == 1);
        assertEquals(List.of("2001:db8:1::c8 443"), harness.dialed(), "an IPv6 flow was dialled by name");

        bindName(harness, "0.0.0.0", "example.org");
        assertEquals(1, harness.runtime.flowCount(), "a name-bind closed an IPv6 flow");
        harness.runtime.shutdown(EPOCH);
    }

    private static void bindName(PeerEgressIpv6Harness harness, String address, String name) {
        harness.runtime.handleFrame(7, PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false,
                PeerEgressFrame.encodeControl(PeerEgressFrame.Control.nameBind(address, name))), EPOCH);
    }

    /** A derived address is the prefix and the mesh IPv4, and goes in and out of packet bytes unchanged. */
    @Test
    void addressesRoundTripThroughPacketBytes() throws IOException {
        PeerEgressIpv6Packet.Address own = consumer6();
        assertArrayEquals(new long[] {0xfd53_7065_6375_7300L, 0x6460_0001L}, own.halves());
        byte[] bytes = new byte[16];
        own.write(bytes, 0);
        assertEquals(own, PeerEgressIpv6Packet.Address.read(bytes, 0));
        assertEquals(own.format(), PeerEgressRuntime.formatTarget(InetAddress.getByAddress(bytes)));
    }
}
