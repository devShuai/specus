package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

/** Real control parser and socket-owning runtime; injected dialer, no external network/device. */
class PeerSessionCloseTests {
    @TempDir Path directory;

    @TestFactory
    Stream<DynamicTest> sharedCloseVectors() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.exists(root.resolve("protocol/test-vectors/peer-session-close-v1.json"))) {
            root = root.getParent();
        }
        assertNotNull(root, "shared close vector not found");
        JsonNode cases = new ObjectMapper().readTree(Files.readString(
                root.resolve("protocol/test-vectors/peer-session-close-v1.json"))).path("cases");
        assertEquals(13, cases.size());
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode scenario : cases) {
            tests.add(DynamicTest.dynamicTest(scenario.path("name").asText(), () -> check(scenario)));
        }
        return tests.stream();
    }

    @SuppressWarnings("unchecked")
    private void check(JsonNode scenario) throws Exception {
        String previousHome = System.getProperty("user.home");
        System.setProperty("user.home", directory.toString());
        PeerMeshClient client = null;
        long now = System.currentTimeMillis();
        List<Socket> sockets = new ArrayList<>();
        PeerEgressRuntime runtime = new PeerEgressRuntime((peer, frame) -> {},
                (protocol, host, port, timeout) -> { Socket socket = new Socket(); sockets.add(socket); return socket; },
                reader -> {}, () -> now);
        try {
            var config = new ClientAuthLoginResponse.PeerMeshConfig();
            config.setClientId(1L);
            client = new PeerMeshClient(config, (target, payload) -> {});
            set(client, "running", true); // Activate only the parser, not STUN, devices or maintenance.
            set(client.egressPlane(), "runtime", runtime);
            Map<Long, PeerMeshClient.PeerSession> sessions = (Map<Long, PeerMeshClient.PeerSession>) get(client, "sessions");
            Map<Long, PeerMeshClient.PeerSession> byId = (Map<Long, PeerMeshClient.PeerSession>) get(client, "sessionsById");
            PeerEgressPolicy policy = new PeerEgressPolicy();
            policy.setEnabled(true);
            policy.setScope(PeerEgressPolicy.SCOPE_PUBLIC);
            policy.setAllowedConsumerClientIds(List.of(7L, 9L));
            var rule = new PeerEgressPolicy.PeerEgressDestinationRule();
            rule.setCidr("203.0.113.0/24");
            rule.setProtocols(List.of("tcp"));
            rule.setPortRanges(List.of(List.of(1, 65535)));
            policy.setDestinationRules(List.of(rule));
            runtime.applyPolicy(policy, PeerEgressAuthorization.Context.defaults(), now);
            install(sessions, byId, runtime, 7, 200, 40000, now);
            install(sessions, byId, runtime, 9, 300, 40001, now);
            assertEquals(2, runtime.flowCount());
            assertEquals(2, sockets.size());
            for (JsonNode message : scenario.path("messages")) client.handleControlMessage(message.toString());
            assertEquals(scenario.path("closedPeerId").asLong() == 0 ? 2 : 1, runtime.flowCount());
            for (int index = 0; index < 2; index++) {
                long peer = index == 0 ? 7 : 9;
                long id = index == 0 ? 200 : 300;
                boolean closed = scenario.path("closedPeerId").asLong() == peer;
                assertEquals(closed ? 1 : 0, sockets.get(index).closes, "peer " + peer + " socket release count");
                assertEquals(!closed, sessions.containsKey(peer), "peer " + peer + " session");
                assertEquals(!closed, byId.containsKey(id), "session index " + id);
            }
            long replacement = scenario.path("replacementSessionId").asLong();
            if (replacement > 0) {
                install(sessions, byId, runtime, 7, replacement, 40002, now);
                assertEquals(3, sockets.size());
                for (JsonNode message : scenario.path("messages")) client.handleControlMessage(message.toString());
                assertNotNull(sessions.get(7L), "replay removed replacement");
                assertEquals(replacement, sessions.get(7L).sessionId());
                assertSame(sessions.get(7L), byId.get(replacement));
                assertEquals(0, sockets.get(2).closes, "replay revoked replacement flow");
                assertEquals(0, sockets.get(1).closes, "replay affected unrelated flow");
                assertTrue(sessions.containsKey(9L));
            }
        } finally {
            runtime.shutdown(now);
            if (client != null) client.close();
            if (previousHome == null) System.clearProperty("user.home");
            else System.setProperty("user.home", previousHome);
        }
    }

    private static void install(Map<Long, PeerMeshClient.PeerSession> sessions,
            Map<Long, PeerMeshClient.PeerSession> byId, PeerEgressRuntime runtime,
            long peer, long id, int port, long now) {
        var session = new PeerMeshClient.PeerSession(id, peer, "token", "", new byte[32]);
        sessions.put(peer, session);
        byId.put(id, session);
        var syn = new PeerEgressSegment.Segment(Ipv4Cidr.parseAddress("100.96.0.1"),
                Ipv4Cidr.parseAddress("203.0.113.10"), port, 443, 1000, 0,
                PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]);
        runtime.handleFrame(peer, PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET,
                false, PeerEgressSegment.build(syn)), now);
    }

    private static Object get(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static void set(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static class Socket implements PeerEgressRuntime.Socket {
        int closes;
        public int read(byte[] buffer) { throw new AssertionError("reader must not run in lifecycle fixture"); }
        public void write(byte[] data) {}
        public void close() { closes++; }
    }
}
