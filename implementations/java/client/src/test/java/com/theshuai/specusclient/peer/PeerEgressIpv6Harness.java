package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.BooleanSupplier;

/**
 * What the IPv6 egress suites share: a runtime over fake sockets that records what it sent and
 * dialled, the shared vector, and the consumer this suite speaks for.
 */
final class PeerEgressIpv6Harness {

    static final long EPOCH = 1_800_000_000_000L;

    /** The session peer's mesh IPv4; its derived address is the only source the egress accepts from it. */
    static final String CONSUMER_MESH = "100.96.0.1";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Object END_OF_STREAM = new Object();

    final PeerEgressRuntime runtime;
    private final List<byte[]> frames = new ArrayList<>();
    private final List<String> dialed = new ArrayList<>();
    private final List<FakeSocket> sockets = new ArrayList<>();

    PeerEgressIpv6Harness(String... destinations) {
        runtime = new PeerEgressRuntime(
                (consumer, frame) -> {
                    synchronized (this) {
                        frames.add(frame.clone());
                    }
                },
                (protocol, host, port, timeoutMs) -> {
                    FakeSocket socket = new FakeSocket();
                    synchronized (this) {
                        dialed.add(host + " " + port);
                        sockets.add(socket);
                    }
                    return socket;
                },
                reader -> Thread.ofVirtual().start(reader),
                () -> EPOCH);
        runtime.applyPolicy(policy(PeerEgressPolicy.SCOPE_PUBLIC, destinations),
                PeerEgressAuthorization.Context.defaults(), EPOCH);
    }

    /** A socket that never fails and reads only what a test hands it. */
    static final class FakeSocket implements PeerEgressRuntime.Socket {
        private final BlockingQueue<Object> events = new LinkedBlockingQueue<>();
        private volatile boolean closed;

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
            System.arraycopy(chunk, 0, buffer, 0, chunk.length);
            return chunk.length;
        }

        @Override
        public void write(byte[] data) {
        }

        @Override
        public void close() {
            if (!closed) {
                closed = true;
                events.offer(new IOException("socket closed"));
            }
        }

        boolean isClosed() {
            return closed;
        }
    }

    static PeerEgressPolicy policy(String scope, String... destinations) {
        List<PeerEgressPolicy.PeerEgressDestinationRule> rules = new ArrayList<>();
        for (String cidr : destinations) {
            PeerEgressPolicy.PeerEgressDestinationRule rule = new PeerEgressPolicy.PeerEgressDestinationRule();
            rule.setCidr(cidr);
            rule.setProtocols(List.of("tcp", "udp"));
            rule.setPortRanges(List.of(List.of(1, 65535)));
            rules.add(rule);
        }
        PeerEgressPolicy built = new PeerEgressPolicy();
        built.setEnabled(true);
        built.setScope(scope);
        built.setAllowedConsumerClientIds(List.of(7L, 9L));
        built.setDestinationRules(rules);
        return built;
    }

    synchronized int dialCount() {
        return dialed.size();
    }

    /** Every dial as "host port", in order. */
    synchronized List<String> dialed() {
        return List.copyOf(dialed);
    }

    synchronized int frameCount() {
        return frames.size();
    }

    synchronized FakeSocket socket(int index) {
        if (index >= sockets.size()) {
            fail("no socket at index " + index + ", only " + sockets.size() + " opened");
        }
        return sockets.get(index);
    }

    private synchronized List<byte[]> snapshot() {
        return List.copyOf(frames);
    }

    /** The IPv6 packets the runtime sent back to a consumer, as written. */
    List<byte[]> packets6() {
        List<byte[]> out = new ArrayList<>();
        for (byte[] raw : snapshot()) {
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw, true);
            if (frame.accepted() && frame.type() == PeerEgressFrame.TYPE_IP_PACKET && frame.inner().ipv6()) {
                out.add(frame.body());
            }
        }
        return out;
    }

    List<PeerEgressSegment.Segment> segments6() {
        List<PeerEgressSegment.Segment> out = new ArrayList<>();
        for (byte[] packet : packets6()) {
            PeerEgressSegment.Segment segment = PeerEgressIpv6Packet.parseSegment(packet);
            if (segment != null) {
                out.add(segment);
            }
        }
        return out;
    }

    /** Every flow-reject the runtime sent. */
    List<PeerEgressFrame.Control> controls() {
        List<PeerEgressFrame.Control> out = new ArrayList<>();
        for (byte[] raw : snapshot()) {
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw, true);
            if (!frame.accepted() || frame.type() != PeerEgressFrame.TYPE_CONTROL) {
                continue;
            }
            PeerEgressFrame.Control control = PeerEgressFrame.decodeControl(frame.body());
            if (control != null && PeerEgressFrame.CONTROL_FLOW_REJECT.equals(control.type())) {
                out.add(control);
            }
        }
        return out;
    }

    List<String> rejectCodes() {
        List<String> codes = new ArrayList<>();
        for (PeerEgressFrame.Control control : controls()) {
            codes.add(control.code());
        }
        return codes;
    }

    static void waitFor(String what, BooleanSupplier condition) {
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

    static byte[] frameFor(byte[] packet) {
        return PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false, packet);
    }

    static PeerEgressIpv6Packet.Address address6(String text) {
        PeerEgressIpv6Packet.Address address = PeerEgressIpv6Packet.Address.parse(text);
        assertNotNull(address, text + " did not parse");
        return address;
    }

    static int address4(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertNotNull(value, dotted + " did not parse");
        return value;
    }

    /** The consumer's own derived address. */
    static PeerEgressIpv6Packet.Address consumer6() {
        return PeerEgressIpv6Packet.deviceAddress(CONSUMER_MESH);
    }

    static PeerEgressSegment.Segment syn6(int sourcePort, String destination, int destinationPort) {
        return new PeerEgressSegment.Segment(0, 0, sourcePort, destinationPort,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0],
                consumer6(), address6(destination));
    }

    static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve("peer-egress-ipv6-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-ipv6-v1.json");
    }
}
