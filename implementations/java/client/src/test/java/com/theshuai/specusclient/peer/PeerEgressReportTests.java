package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.client.NettyClient;
import io.netty.channel.Channel;
import io.netty.channel.embedded.EmbeddedChannel;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.util.StringUtils;

/**
 * The {@code egress-report} as it leaves a running egress: built from the plane's own numbers,
 * checked on the plane's schedule, and sent over the control connection the way the server accepts
 * it.
 *
 * <p>The vector suite pins the decisions; this one pins the wiring. The clock and the schedule are
 * the test's, so a minute between checks costs nothing, while the counts come from real flows and
 * real refusals going through the plane.
 */
class PeerEgressReportTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String VIRTUAL_IP = "100.96.0.1";
    private static final long T0 = 1_791_000_000_000L;

    /** Every key a report may carry, in the spec's order. */
    private static final List<String> REPORT_KEYS = List.of(
            "type", "revision", "activeFlows", "totalFlows", "rejectedFlows", "bytesIn", "bytesOut");

    /** What the server binds from the connection and refuses in the body, even as null. */
    private static final List<String> SERVER_BOUND = List.of(
            "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
            "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
            "sessionId", "token");

    @TempDir
    Path directory;

    private final List<byte[]> frames = new ArrayList<>();
    private final List<String> reports = new ArrayList<>();
    private final List<Long> periods = new ArrayList<>();
    private final List<Runnable> checks = new ArrayList<>();
    private long wallMs = T0;
    private PeerEgressMesh mesh;

    @AfterEach
    void stop() {
        if (mesh != null) {
            mesh.close();
        }
    }

    private final class FakeHost implements PeerEgressMesh.Host {
        @Override
        public boolean sendToPeer(long peerId, byte[] frame) {
            synchronized (PeerEgressReportTests.this) {
                frames.add(frame.clone());
            }
            return true;
        }

        @Override
        public void sendControl(String message) {
            synchronized (PeerEgressReportTests.this) {
                reports.add(message);
            }
        }

        @Override
        public void writeToDevice(byte[] packet) {
        }

        @Override
        public String tunName() {
            return "specus0";
        }

        @Override
        public String meshCidr() {
            return "100.96.0.0/11";
        }

        @Override
        public String virtualIp() {
            return VIRTUAL_IP;
        }

        @Override
        public List<String> deploymentDenyCidrs() {
            return List.of("203.0.113.250/32");
        }

        @Override
        public List<String> peerEndpointAddresses() {
            return List.of();
        }

        @Override
        public Integer pathMtuForPeer(long peerId) {
            return null;
        }

        @Override
        public Path routeJournalPath() {
            return directory.resolve("egress-routes.json");
        }
    }

    /** A routing table that accepts everything and touches nothing on this machine. */
    private static final class FakeCommander implements PeerEgressRouteInstaller.Commander {
        @Override
        public PeerEgressRouteInstaller.Conflict conflict(PeerEgressRoutePlanner.Route route) {
            return PeerEgressRouteInstaller.Conflict.none();
        }

        @Override
        public void install(PeerEgressRoutePlanner.Route route) {
        }

        @Override
        public void remove(PeerEgressRoutePlanner.Route route) {
        }
    }

    /** A socket that connects at once and never reads, so a flow stays open and moves no bytes. */
    private static final class FakeDialer implements PeerEgressRuntime.Dialer {
        @Override
        public PeerEgressRuntime.Socket dial(String protocol, String host, int port, long timeoutMs) {
            return new PeerEgressRuntime.Socket() {
                private final java.util.concurrent.CountDownLatch closed =
                        new java.util.concurrent.CountDownLatch(1);

                @Override
                public int read(byte[] buffer) {
                    try {
                        closed.await();
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    return -1;
                }

                @Override
                public void write(byte[] data) {
                }

                @Override
                public void close() {
                    closed.countDown();
                }
            };
        }
    }

    /** Takes the plane's schedule and clock, so the test runs the checks and says what time it is. */
    private void takeSchedule(PeerEgressMesh plane) {
        plane.reportScheduler = (periodMs, task) -> {
            periods.add(periodMs);
            checks.add(task);
        };
        plane.wallClock = () -> wallMs;
    }

    private void check() {
        assertEquals(1, checks.size(), "the report check was not scheduled exactly once");
        checks.get(0).run();
    }

    private synchronized List<String> sent() {
        return List.copyOf(reports);
    }

    private synchronized List<byte[]> sentFrames() {
        return List.copyOf(frames);
    }

    private static void waitFor(String what, BooleanSupplier condition) {
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

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertNotNull(value, dotted + " did not parse");
        return value;
    }

    private static byte[] synTo(String destination, int port) {
        return PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false,
                PeerEgressSegment.build(new PeerEgressSegment.Segment(
                        address(VIRTUAL_IP), address(destination), 40000, port,
                        1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0])));
    }

    private static String configFor(long revision, boolean enabled) {
        if (!enabled) {
            return "{\"type\":\"egress-config\",\"enabled\":false,\"revision\":" + revision + "}";
        }
        return "{\"type\":\"egress-config\",\"enabled\":true,\"revision\":" + revision
                + ",\"scope\":\"PUBLIC\",\"allowedConsumerClientIds\":[7],"
                + "\"destinationRules\":[{\"cidr\":\"203.0.113.0/24\",\"protocols\":[\"tcp\",\"udp\"],"
                + "\"portRanges\":[[1,65535]]}],"
                + "\"limits\":{\"maxConcurrentFlows\":8,\"maxFlowsPerConsumer\":4,\"idleTimeoutSeconds\":60}}";
    }

    private static boolean isControl(byte[] raw) {
        PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
        return frame.accepted() && frame.type() == PeerEgressFrame.TYPE_CONTROL;
    }

    private static boolean isSynAck(byte[] raw) {
        PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
        if (!frame.accepted() || frame.type() != PeerEgressFrame.TYPE_IP_PACKET) {
            return false;
        }
        PeerEgressSegment.Segment segment = PeerEgressSegment.parse(frame.body());
        return segment != null && segment.has(PeerEgressSegment.FLAG_SYN) && segment.has(PeerEgressSegment.FLAG_ACK);
    }

    /**
     * The keys of a report and nothing else, in order. Above all none the server binds itself: it
     * refuses a report that carries one, null or not.
     */
    private static JsonNode body(String message) throws Exception {
        JsonNode body = MAPPER.readTree(message);
        List<String> keys = new ArrayList<>();
        for (Map.Entry<String, JsonNode> entry : body.properties()) {
            keys.add(entry.getKey());
        }
        assertEquals(REPORT_KEYS, keys, "the report's keys");
        for (String field : SERVER_BOUND) {
            assertFalse(body.has(field), "the report carries " + field);
        }
        assertEquals("egress-report", body.path("type").asText());
        return body;
    }

    /** The report says what the local status says: one source, one meaning. */
    @SuppressWarnings("unchecked")
    private static void assertMatchesStatus(JsonNode report, Map<String, Object> status) throws Exception {
        Map<String, Object> egress = (Map<String, Object>) status.get("egress");
        assertEquals(((Number) egress.get("flows")).longValue(), report.path("activeFlows").asLong(), "activeFlows");
        assertEquals(((Number) egress.get("totalFlows")).longValue(), report.path("totalFlows").asLong(), "totalFlows");
        assertEquals(((Number) egress.get("bytesIn")).longValue(), report.path("bytesIn").asLong(), "bytesIn");
        assertEquals(((Number) egress.get("bytesOut")).longValue(), report.path("bytesOut").asLong(), "bytesOut");
        assertEquals(MAPPER.readTree(MAPPER.writeValueAsString(egress.get("refused"))), report.path("rejectedFlows"),
                "rejectedFlows");
    }

    /**
     * A running egress reports its status numbers through the host's control path: a flow it opened
     * and a destination it refused, once per change and once per control session, and nothing
     * while it is switched off.
     */
    @Test
    void anEgressReportsItsOwnNumbersToTheServer() throws Exception {
        mesh = new PeerEgressMesh(new FakeHost(), new FakeDialer(), new FakeCommander());
        takeSchedule(mesh);
        assertTrue(checks.isEmpty(), "a node that is no egress scheduled reports");

        mesh.applyEgressConfig(configFor(1, true));
        assertEquals(List.of(PeerEgressReporter.INTERVAL_MS), periods, "the check's period");

        mesh.handleInboundFrame(7, synTo("203.0.113.10", 443));
        waitFor("the flow to open", () -> sentFrames().stream().anyMatch(PeerEgressReportTests::isSynAck));
        mesh.handleInboundFrame(7, synTo("198.51.100.10", 443));
        waitFor("the refusal", () -> sentFrames().stream().anyMatch(PeerEgressReportTests::isControl));

        check();
        assertEquals(1, sent().size(), "the first check of a session did not report");
        JsonNode first = body(sent().get(0));
        assertEquals(T0, first.path("revision").asLong(), "the revision is the wall clock");
        assertEquals(1, first.path("activeFlows").asLong());
        assertEquals(1, first.path("totalFlows").asLong());
        assertEquals(MAPPER.readTree("{\"EGRESS_DEST_DENIED\":1}"), first.path("rejectedFlows"));
        assertMatchesStatus(first, mesh.status());

        wallMs = T0 + PeerEgressReporter.INTERVAL_MS;
        check();
        assertEquals(1, sent().size(), "an unchanged egress reported again");

        // A new control session reports at its first check, unchanged or not, and a clock that
        // stepped back still moves the revision forward.
        mesh.newControlSession();
        wallMs = T0 - 5_000;
        check();
        assertEquals(2, sent().size(), "a new session was not reported to");
        JsonNode again = body(sent().get(1));
        assertEquals(T0 + 1, again.path("revision").asLong(), "the revision went backwards");
        assertEquals(first.path("rejectedFlows"), again.path("rejectedFlows"));

        // Switched off: nothing is sent. Switched on again: the first check reports.
        mesh.applyEgressConfig(configFor(2, false));
        wallMs = T0 + 2 * PeerEgressReporter.INTERVAL_MS;
        check();
        assertEquals(2, sent().size(), "a switched-off egress reported");
        mesh.applyEgressConfig(configFor(3, true));
        wallMs = T0 + 3 * PeerEgressReporter.INTERVAL_MS;
        check();
        assertEquals(3, sent().size(), "the first check after switching on did not report");
        JsonNode resumed = body(sent().get(2));
        assertEquals(wallMs, resumed.path("revision").asLong());
        // Running totals: the flow the switch closed stays counted, and so does why it closed.
        assertEquals(0, resumed.path("activeFlows").asLong());
        assertEquals(1, resumed.path("totalFlows").asLong());
        assertEquals(1, resumed.path("rejectedFlows").path(PeerEgressCodes.DEST_DENIED).asLong());
        assertEquals(1, resumed.path("rejectedFlows").path(PeerEgressCodes.DISABLED).asLong());
        assertMatchesStatus(resumed, mesh.status());
    }

    /** A plane that never got an egress-config is no egress: it schedules and sends nothing. */
    @Test
    void aNodeThatIsNoEgressNeverReports() {
        mesh = new PeerEgressMesh(new FakeHost(), new FakeDialer(), new FakeCommander());
        takeSchedule(mesh);

        mesh.newControlSession();
        mesh.checkReport();

        assertTrue(checks.isEmpty(), "a report check was scheduled");
        assertTrue(sent().isEmpty(), "a report was sent");
    }

    /**
     * The whole path out of the client: the plane's report reaches the control connection as a
     * PEER_CONTROL message addressed to no client, which is the envelope the server takes a report
     * in. Any target name, like any identity in the body, is refused there.
     */
    @Test
    void theReportLeavesOnTheControlConnectionAddressedToNoClient() throws Exception {
        String previousHome = System.getProperty("user.home");
        System.setProperty("user.home", directory.toString());
        EmbeddedChannel channel = new EmbeddedChannel();
        PeerMeshClient client = null;
        try {
            SpecusBean bean = new SpecusBean();
            bean.setClientName("unit-client");
            bean.setClientSessionId(1L);
            bean.setAccessToken("cs_unit_token");
            bean.setRemoteAddress("127.0.0.1");
            bean.setRemotePort(7010);
            NettyClient netty = new NettyClient(bean);
            this.<AtomicReference<Channel>>field(netty, "controlChannel").set(channel);
            client = field(netty, "peerMeshClient");
            PeerEgressMesh plane = client.egressPlane();
            takeSchedule(plane);

            plane.applyEgressConfig(configFor(1, true));
            // Refused before anything is dialled, so the real dialer never runs.
            plane.handleInboundFrame(7, synTo("198.51.100.10", 443));
            check();

            MessageRequestPacket packet = assertInstanceOf(MessageRequestPacket.class, channel.readOutbound());
            assertEquals(MessageType.PEER_CONTROL, packet.getMessageType());
            assertFalse(StringUtils.hasText(packet.getToClientName()), "the report named a target client");
            assertEquals("unit-client", packet.getClientName());
            JsonNode report = body(packet.getMessage());
            assertEquals(T0, report.path("revision").asLong());
            assertEquals(0, report.path("activeFlows").asLong());
            assertEquals(0, report.path("totalFlows").asLong());
            assertEquals(MAPPER.readTree("{\"EGRESS_DEST_DENIED\":1}"), report.path("rejectedFlows"));
            assertMatchesStatus(report, client.egressStatus());
            assertNull(channel.readOutbound(), "one check sent more than one message");

            // Unchanged, the next check is quiet; a login starts a new control session, after which
            // the next check reports again.
            check();
            assertNull(channel.readOutbound(), "an unchanged egress reported again");
            client.onControlSession();
            check();
            MessageRequestPacket next = assertInstanceOf(MessageRequestPacket.class, channel.readOutbound());
            assertEquals(T0 + 1, body(next.getMessage()).path("revision").asLong());
        } finally {
            if (client != null) {
                client.close();
            }
            channel.finishAndReleaseAll();
            if (previousHome == null) {
                System.clearProperty("user.home");
            } else {
                System.setProperty("user.home", previousHome);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T field(Object owner, String name) throws ReflectiveOperationException {
        Field field = owner.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return (T) field.get(owner);
    }
}
