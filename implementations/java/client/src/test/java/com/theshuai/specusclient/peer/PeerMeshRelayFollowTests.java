package com.theshuai.specusclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A session follows its peer onto the relay only when the peer has gone quiet on the direct path.
 * Following every relayed frame let frames already in flight on the two paths flip both sides back
 * and forth, and under load the two sides never settled on one path.
 */
class PeerMeshRelayFollowTests {
    private static final long LOCAL_ID = 1L;
    private static final long PEER_ID = 2L;
    private static final long SESSION_ID = 4242L;
    private static final InetSocketAddress DIRECT = new InetSocketAddress("203.0.113.9", 42000);

    @TempDir
    Path tempDir;

    private String previousHome;
    private PeerMeshClient client;
    private PeerMeshClient.PeerSession session;
    private long sequence;

    @BeforeEach
    void setUp() throws Exception {
        previousHome = System.getProperty("user.home");
        System.setProperty("user.home", tempDir.toString());
        ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
        config.setClientId(LOCAL_ID);
        config.setVirtualIp("100.96.0.1");
        config.setCidr("100.96.0.0/11");
        config.setTurnHost("198.51.100.20");
        config.setTurnPort(3478);
        client = new PeerMeshClient(config, (target, payload) -> {
        });
        // A fresh key for every test: the cipher is shared per thread and refuses a key and nonce
        // it has already encrypted with.
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        session = new PeerMeshClient.PeerSession(SESSION_ID, PEER_ID, "token", "", key);
        session.setLocalKeyEpoch("epoch-local");
        session.applyRemoteKeyEpoch("epoch-remote");
        sessions("sessions").put(PEER_ID, session);
        sessions("sessionsById").put(SESSION_ID, session);
        set("remoteEndpoint", DIRECT);
    }

    @AfterEach
    void tearDown() {
        client.close();
        if (previousHome == null) {
            System.clearProperty("user.home");
        } else {
            System.setProperty("user.home", previousHome);
        }
    }

    @Test
    void relayFrameDoesNotMoveASessionThatStillHearsItsPeerDirect() throws Exception {
        set("lastDirectSuccessMillis", System.currentTimeMillis());

        receiveFrame("allocation-1");

        assertThat((String) get("relayTargetAllocationId")).isNull();
        assertThat((InetSocketAddress) get("remoteEndpoint")).isEqualTo(DIRECT);
        assertThat((long) get("lastRelaySuccessMillis"))
                .as("the relay delivered a frame, and that success is still recorded").isPositive();
    }

    @Test
    void relayFrameMovesASessionWhoseDirectPathWentQuiet() throws Exception {
        set("lastDirectSuccessMillis",
                System.currentTimeMillis() - PeerMeshClient.RELAY_FOLLOW_QUIET_MILLIS - 1_000);

        receiveFrame("allocation-1");

        assertThat((String) get("relayTargetAllocationId")).isEqualTo("allocation-1");
    }

    @Test
    void directFrameCountsAsHearingThePeerDirect() throws Exception {
        receiveFrame(null);

        assertThat((long) get("lastDirectSuccessMillis")).isPositive();
        receiveFrame("allocation-1");
        assertThat((String) get("relayTargetAllocationId")).isNull();
    }

    @Test
    void relayCheckDoesNotMoveAHealthyDirectSession() throws Exception {
        set("lastDirectSuccessMillis", System.currentTimeMillis() - 10_000);

        markPathFromInboundCheck("allocation-1");

        assertThat((String) get("relayTargetAllocationId")).isNull();
        assertThat((InetSocketAddress) get("remoteEndpoint")).isEqualTo(DIRECT);
    }

    @Test
    void relayCheckMovesASessionWithoutAHealthyDirectPath() throws Exception {
        markPathFromInboundCheck("allocation-1");

        assertThat((String) get("relayTargetAllocationId")).isEqualTo("allocation-1");
    }

    /**
     * A peer that restarted answers from a new socket. What this side learned about the old one must
     * not keep the session on a socket whose process is gone, whether the new process is heard
     * direct or over the relay first.
     */
    @Test
    void aPeerRestartLetsItsNewEndpointTakeOver() throws Exception {
        long now = System.currentTimeMillis();
        set("lastDirectSuccessMillis", now);
        set("endpointSuccessMillis", now);
        set("endpointRtt", 1L);
        set("currentPathType", "DIRECT");
        assertThat(session.applyRemoteKeyEpoch("epoch-restarted")).as("a second epoch is a restart").isTrue();

        InetSocketAddress fresh = new InetSocketAddress("203.0.113.9", 43000);
        markPathFromInboundCheck(fresh, null);

        assertThat((InetSocketAddress) get("remoteEndpoint")).isEqualTo(fresh);
    }

    @Test
    void aPeerRestartLetsItsRelayCheckTakeOver() throws Exception {
        long now = System.currentTimeMillis();
        set("lastDirectSuccessMillis", now);
        set("endpointSuccessMillis", now);
        session.applyRemoteKeyEpoch("epoch-restarted");

        markPathFromInboundCheck("allocation-9");

        assertThat((String) get("relayTargetAllocationId")).isEqualTo("allocation-9");
    }

    private void markPathFromInboundCheck(InetSocketAddress remote, String relayFrom) throws Exception {
        Method method = PeerMeshClient.class.getDeclaredMethod(
                "markPathFromInboundCheck", PeerMeshClient.PeerSession.class, InetSocketAddress.class, String.class);
        method.setAccessible(true);
        method.invoke(client, session, remote, relayFrom);
    }

    private void receiveFrame(String relayFrom) throws Exception {
        byte[] frame = PeerDataFrameCodec.encode(
                session.inboundTrafficKey(LOCAL_ID), SESSION_ID, ++sequence, new byte[] {1, 2, 3, 4});
        Method method = PeerMeshClient.class.getDeclaredMethod(
                "handleDataFrame", byte[].class, InetSocketAddress.class, String.class);
        method.setAccessible(true);
        method.invoke(client, frame, DIRECT, relayFrom);
    }

    private void markPathFromInboundCheck(String relayFrom) throws Exception {
        Method method = PeerMeshClient.class.getDeclaredMethod(
                "markPathFromInboundCheck", PeerMeshClient.PeerSession.class, InetSocketAddress.class, String.class);
        method.setAccessible(true);
        method.invoke(client, session, DIRECT, relayFrom);
    }

    @SuppressWarnings("unchecked")
    private Map<Long, PeerMeshClient.PeerSession> sessions(String name) throws Exception {
        Field field = PeerMeshClient.class.getDeclaredField(name);
        field.setAccessible(true);
        return (Map<Long, PeerMeshClient.PeerSession>) field.get(client);
    }

    private void set(String name, Object value) throws Exception {
        Field field = PeerMeshClient.PeerSession.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(session, value);
    }

    private Object get(String name) throws Exception {
        Field field = PeerMeshClient.PeerSession.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(session);
    }
}
