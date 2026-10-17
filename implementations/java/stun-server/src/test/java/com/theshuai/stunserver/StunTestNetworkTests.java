package com.theshuai.stunserver;

import com.theshuai.common.stun.StunEndpointTopology;
import org.junit.jupiter.api.Test;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class StunTestNetworkTests {
    @Test
    void clientAllocationSeesEveryStandaloneEndpointAlreadyBound() throws Exception {
        InetAddress address = InetAddress.getLoopbackAddress();
        int first = freePort(address);
        int second = freePort(address);
        while (first == second) second = freePort(address);
        List<InetSocketAddress> endpoints = List.of(
                new InetSocketAddress(address, first), new InetSocketAddress(address, second));
        StandaloneStunServer server = server(endpoints.get(0), endpoints.get(1));
        try (StunTestNetwork network = StunTestNetwork.start(List.of(server), () -> {
            assertBound(endpoints);
            return new DatagramSocket(new InetSocketAddress(address, 0));
        })) {
            assertTrue(server.isRunning());
            assertTrue(network.client().isBound());
        }
        assertFree(endpoints);
    }

    @Test
    void clientAllocationSeesEveryServerBoundNotOnlyTheFirst() throws Exception {
        InetAddress address = InetAddress.getLoopbackAddress();
        int first = freePort(address);
        int second = freePort(address);
        while (first == second) second = freePort(address);
        List<InetSocketAddress> endpoints = List.of(
                new InetSocketAddress(address, first), new InetSocketAddress(address, second));
        StandaloneStunServer firstServer = server(endpoints.get(0), null);
        StandaloneStunServer secondServer = server(endpoints.get(1), null);
        try (StunTestNetwork ignored = StunTestNetwork.start(List.of(firstServer, secondServer), () -> {
            assertBound(endpoints);
            return new DatagramSocket(new InetSocketAddress(address, 0));
        })) {
            assertTrue(firstServer.isRunning()); assertTrue(secondServer.isRunning());
        }
        assertFree(endpoints);
    }

    @Test
    void failedClientAllocationClosesAllOwnedServers() throws Exception {
        InetSocketAddress endpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), freePort(InetAddress.getLoopbackAddress()));
        StandaloneStunServer server = server(endpoint, null);
        SocketException failure = new SocketException("deliberate fixture client failure");
        assertSame(failure, assertThrows(SocketException.class, () -> StunTestNetwork.start(
                List.of(server), () -> { throw failure; })));
        assertFalse(server.isRunning());
        assertFree(List.of(endpoint));
    }

    @Test
    void laterServerBindFailureClosesEarlierServersAndTheClient() throws Exception {
        InetAddress address = InetAddress.getLoopbackAddress();
        // Hold this client before choosing ports so it cannot accidentally take the
        // first server's intended endpoint in the baseline lifecycle control case.
        try (DatagramSocket client = new DatagramSocket(new InetSocketAddress(address, 0));
             DatagramSocket blocker = new DatagramSocket(new InetSocketAddress(address, 0))) {
            InetSocketAddress firstEndpoint = new InetSocketAddress(address, freePort(address));
            InetSocketAddress blockedEndpoint = new InetSocketAddress(address, blocker.getLocalPort());
            StandaloneStunServer first = server(firstEndpoint, null);
            StandaloneStunServer blocked = server(blockedEndpoint, null);
            SocketException failure = assertThrows(SocketException.class, () -> StunTestNetwork.start(
                    List.of(first, blocked), () -> client));
            assertTrue(failure.getMessage().contains(":" + blocker.getLocalPort()));
            assertFalse(first.isRunning()); assertFalse(blocked.isRunning());
            // If the factory was never called (fixed server-first order), the
            // caller still owns this socket and the surrounding try closes it.
            assertFree(List.of(firstEndpoint));
        }
    }

    private static StandaloneStunServer server(InetSocketAddress first, InetSocketAddress second) {
        return new StandaloneStunServer(new StandaloneStunServerConfig(StunEndpointTopology.basic(
                new StunEndpointTopology.Endpoint(StunEndpointTopology.PRIMARY, first, first),
                second == null ? null : new StunEndpointTopology.Endpoint(StunEndpointTopology.PRIMARY_ALTERNATE_PORT, second, second)),
                "test-owned-network", false));
    }

    private static int freePort(InetAddress address) throws Exception {
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(address, 0))) {
            return socket.getLocalPort();
        }
    }

    private static void assertBound(List<InetSocketAddress> endpoints) {
        for (InetSocketAddress endpoint : endpoints) {
            assertThrows(SocketException.class, () -> {
                try (DatagramSocket ignored = new DatagramSocket(endpoint)) { }
            }, "server must reserve " + endpoint + " before the test client chooses an ephemeral port");
        }
    }

    private static void assertFree(List<InetSocketAddress> endpoints) throws Exception {
        for (InetSocketAddress endpoint : endpoints) {
            try (DatagramSocket socket = new DatagramSocket(endpoint)) { assertTrue(socket.isBound()); }
        }
    }
}
