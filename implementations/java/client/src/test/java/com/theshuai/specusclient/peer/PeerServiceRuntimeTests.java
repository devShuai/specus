package com.theshuai.specusclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.peermesh.LocalPeerService;
import com.theshuai.common.peermesh.PeerAdvertisedService;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.peermesh.PeerServiceSharingStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.assertj.core.api.Assertions.assertThat;

class PeerServiceRuntimeTests {
    private final List<String> sent = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private PeerServiceRuntime runtime;

    @AfterEach
    void tearDown() {
        if (runtime != null) {
            runtime.close();
        }
        scheduler.shutdownNow();
    }

    @Test
    void doesNotProbeOrReportWhenSharingIsOff() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setHasAuthorizedOnlinePeer(true);
            runtime.applyConfig(config(false, localService(port, true)));
            Thread.sleep(50);
            assertThat(sent).isEmpty();
            assertThat(runtime.remoteServices()).isEmpty();
        }
    }

    @Test
    void doesNotProbeWithoutAuthorizedOnlinePeer() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setHasAuthorizedOnlinePeer(false);
            runtime.applyConfig(config(true, localService(port, true)));
            Thread.sleep(50);
            assertThat(sent).isEmpty();
        }
    }

    @Test
    void reportsReachableEnabledServiceAndBuildsSafeCatalogUrl() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setRosterLookup(id -> new PeerServiceRuntime.RosterHint("100.96.0.2", true));
            runtime.setHasAuthorizedOnlinePeer(true);
            runtime.applyConfig(config(true, localService(port, true)));
            waitUntil(() -> !sent.isEmpty());
            assertThat(sent.getFirst()).contains("service-report");
            assertThat(sent.getFirst()).contains("svc-http01");
            assertThat(sent.getFirst()).doesNotContain("targetHost");

            PeerControlMessage catalog = catalogMessage();
            runtime.applyCatalog(catalog);
            List<PeerServiceRuntime.RemoteServiceView> views = runtime.remoteServices();
            assertThat(views).hasSize(1);
            assertThat(views.getFirst().openable()).isTrue();
            assertThat(views.getFirst().accessTarget()).isEqualTo("http://100.96.0.2:8080/app");
            assertThat(views.getFirst().accessTarget()).doesNotContain("evil");
        }
    }

    @Test
    void localPauseStopsReportingWithoutChangingServerConfig() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setHasAuthorizedOnlinePeer(true);
            runtime.applyConfig(config(true, localService(port, true)));
            waitUntil(() -> !sent.isEmpty());
            sent.clear();
            runtime.setLocalPublished("svc-http01", false);
            waitUntil(() -> sent.stream().anyMatch(body -> body.contains("\"enabled\":false")
                    || body.contains("\"services\":[]")
                    || body.contains("\"services\": []")));
            assertThat(runtime.isLocallyPublished("svc-http01")).isFalse();
        }
    }

    @Test
    void turningSharingOffWithdrawsPreviousReport() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setHasAuthorizedOnlinePeer(true);
            runtime.applyConfig(config(true, localService(port, true)));
            waitUntil(() -> !sent.isEmpty());
            sent.clear();
            runtime.applyConfig(config(false, localService(port, true)));
            waitUntil(() -> sent.stream().anyMatch(body -> body.contains("\"enabled\":false")));
            assertThat(sent.getLast()).contains("service-report");
            assertThat(sent.getLast()).contains("\"enabled\":false");
        }
    }

    @Test
    void emptyCatalogWithdrawsAndOfflinePublisherDisablesOpen() {
        runtime = newRuntime();
        runtime.applyConfig(config(true, localService(1, false)));
        runtime.setRosterLookup(id -> new PeerServiceRuntime.RosterHint("100.96.0.2", false));
        runtime.applyCatalog(catalogMessage());
        assertThat(runtime.remoteServices().getFirst().openable()).isFalse();
        assertThat(runtime.remoteServices().getFirst().unavailableReason()).contains("离线");

        PeerControlMessage empty = catalogMessage();
        empty.setRevision(2L);
        empty.setServices(List.of());
        runtime.applyCatalog(empty);
        assertThat(runtime.remoteServices()).isEmpty();
    }

    @Test
    void staleCatalogCannotRollBackOrReviveWithdrawnServices() {
        runtime = newRuntime();
        runtime.applyConfig(config(true, localService(1, false)));
        PeerControlMessage newest = catalogMessage();
        newest.setRevision(2L);
        runtime.applyCatalog(newest);
        PeerControlMessage stale = catalogMessage();
        stale.setRevision(1L);
        runtime.applyCatalog(stale);
        assertThat(runtime.remoteServices()).hasSize(1);

        PeerControlMessage withdrawn = catalogMessage();
        withdrawn.setRevision(3L);
        withdrawn.setServices(List.of());
        runtime.applyCatalog(withdrawn);
        runtime.applyCatalog(newest);
        assertThat(runtime.remoteServices()).isEmpty();
    }

    @Test
    void reconnectClearsCatalogRevisionHighWaterAndAcceptsCurrentSnapshot() {
        runtime = newRuntime();
        runtime.applyConfig(config(true, localService(1, false)));
        runtime.setRosterLookup(id -> new PeerServiceRuntime.RosterHint("100.96.0.2", true));
        runtime.setHasAuthorizedOnlinePeer(true);
        PeerControlMessage current = catalogMessage();
        current.setRevision(7L);
        runtime.applyCatalog(current);
        assertThat(runtime.remoteServices()).hasSize(1);

        runtime.setHasAuthorizedOnlinePeer(false);
        assertThat(runtime.remoteServices()).isEmpty();
        runtime.setHasAuthorizedOnlinePeer(true);
        runtime.applyCatalog(current);

        assertThat(runtime.remoteServices()).hasSize(1);
    }

    @Test
    void unchangedServicesAreRenewedAcrossMultipleCatalogTtls() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setHasAuthorizedOnlinePeer(true);
            runtime.applyConfig(config(true, localService(port, true)));
            waitUntil(() -> !sent.isEmpty());
            sent.clear();
            for (int elapsedTtls = 1; elapsedTtls <= 3; elapsedTtls++) {
                runtime.lastReportAt = Instant.now()
                        .minus(PeerServiceRuntime.REPORT_REFRESH_INTERVAL)
                        .minusSeconds(1);
                runtime.probeAndReport();
                assertThat(sent).hasSize(elapsedTtls);
            }
        }
    }

    @Test
    void probeTcpDetectsOpenAndClosedPorts() throws Exception {
        int port = freePort();
        assertThat(PeerServiceDiscovery.probeTcp("127.0.0.1", port, 200)).isFalse();
        try (ServerSocket ignored = listen(port)) {
            assertThat(PeerServiceDiscovery.probeTcp("127.0.0.1", port, 400)).isTrue();
        }
    }

    @Test
    void tcpBridgeRejectsSourceOutsideServerAuthoredAcl() throws Exception {
        int targetPort = freePort();
        int publishedPort = freePort();
        LocalPeerService local = localService(targetPort, true);
        local.setPublishedPort(publishedPort);
        local.setAllowedPeerVirtualIps(List.of("127.0.0.2"));
        try (ServerSocket target = listen(targetPort);
             PeerServiceBridge bridge = PeerServiceBridge.bind("127.0.0.1", local);
             Socket caller = new Socket("127.0.0.1", publishedPort)) {
            target.setSoTimeout(250);
            assertThat(org.assertj.core.api.Assertions.catchThrowable(target::accept))
                    .isInstanceOf(SocketTimeoutException.class);
            assertThat(caller.getInputStream().read()).isEqualTo(-1);
        }
    }

    @Test
    void tcpBridgeAllowsServerAuthorizedSource() throws Exception {
        int targetPort = freePort();
        int publishedPort = freePort();
        LocalPeerService local = localService(targetPort, true);
        local.setPublishedPort(publishedPort);
        local.setAllowedPeerVirtualIps(List.of("127.0.0.1"));
        try (ServerSocket target = listen(targetPort);
             PeerServiceBridge bridge = PeerServiceBridge.bind("127.0.0.1", local);
             Socket caller = new Socket("127.0.0.1", publishedPort);
             Socket forwarded = target.accept()) {
            assertThat(forwarded.isConnected()).isTrue();
        }
    }

    @Test
    void tcpBridgeSeparatesThreePeersAndRevocationClosesTheActiveFlow() throws Exception {
        int targetPort = freePort();
        int publishedPort = freePort();
        LocalPeerService local = localService(targetPort, true);
        local.setPublishedPort(publishedPort);
        local.setAllowedPeerVirtualIps(List.of("127.0.0.2"));
        try (ServerSocket target = listen(targetPort);
             PeerServiceBridge bridge = PeerServiceBridge.bind("127.0.0.1", local);
             Socket denied = connectFrom("127.0.0.3", publishedPort)) {
            target.setSoTimeout(250);
            assertThat(org.assertj.core.api.Assertions.catchThrowable(target::accept))
                    .isInstanceOf(SocketTimeoutException.class);

            try (Socket allowed = connectFrom("127.0.0.2", publishedPort)) {
                target.setSoTimeout(1_000);
                try (Socket forwarded = target.accept()) {
                    assertThat(forwarded.isConnected()).isTrue();
                    allowed.setSoTimeout(1_000);
                    bridge.close();
                    int result;
                    try {
                        result = allowed.getInputStream().read();
                    } catch (IOException closed) {
                        result = -1;
                    }
                    assertThat(result).isEqualTo(-1);
                }
            }
            assertThat(org.assertj.core.api.Assertions.catchThrowable(
                    () -> connectFrom("127.0.0.2", publishedPort)))
                    .isInstanceOf(IOException.class);
        }
    }

    @Test
    void udpBridgeAppliesTheSameAclAndRevocationBoundary() throws Exception {
        byte[] payload = {1, 2, 3};
        try (DatagramSocket target = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             DatagramSocket denied = new DatagramSocket(new InetSocketAddress("127.0.0.3", 0));
             DatagramSocket allowed = new DatagramSocket(new InetSocketAddress("127.0.0.2", 0))) {
            int publishedPort = freeUdpPort();
            LocalPeerService local = localService(target.getLocalPort(), true);
            local.setTransport("udp");
            local.setApplication("udp");
            local.setPublishedPort(publishedPort);
            local.setAllowedPeerVirtualIps(List.of("127.0.0.2"));
            try (PeerServiceUdpBridge bridge = PeerServiceUdpBridge.bind("127.0.0.1", local)) {
                denied.send(new DatagramPacket(payload, payload.length,
                        new InetSocketAddress("127.0.0.1", publishedPort)));
                target.setSoTimeout(250);
                assertThat(org.assertj.core.api.Assertions.catchThrowable(
                        () -> target.receive(new DatagramPacket(new byte[8], 8))))
                        .isInstanceOf(SocketTimeoutException.class);

                allowed.send(new DatagramPacket(payload, payload.length,
                        new InetSocketAddress("127.0.0.1", publishedPort)));
                target.setSoTimeout(1_000);
                DatagramPacket forwarded = new DatagramPacket(new byte[8], 8);
                target.receive(forwarded);
                assertThat(forwarded.getLength()).isEqualTo(payload.length);

                bridge.close();
                allowed.send(new DatagramPacket(payload, payload.length,
                        new InetSocketAddress("127.0.0.1", publishedPort)));
                target.setSoTimeout(250);
                assertThat(org.assertj.core.api.Assertions.catchThrowable(
                        () -> target.receive(new DatagramPacket(new byte[8], 8))))
                        .isInstanceOf(SocketTimeoutException.class);
            }
        }
    }

    private static Socket connectFrom(String sourceIp, int targetPort) throws IOException {
        Socket socket = new Socket();
        try {
            socket.bind(new InetSocketAddress(InetAddress.getByName(sourceIp), 0));
            socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), targetPort));
            return socket;
        } catch (IOException failure) {
            socket.close();
            throw failure;
        }
    }

    private static int freeUdpPort() throws IOException {
        try (DatagramSocket socket = new DatagramSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private PeerServiceRuntime newRuntime() {
        return new PeerServiceRuntime((to, message) -> sent.add(message), scheduler);
    }

    private static ClientAuthLoginResponse.PeerMeshConfig config(boolean sharing, LocalPeerService local) {
        ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
        config.setEnabled(true);
        config.setVirtualIp("127.0.0.1");
        config.setServiceSharing(PeerServiceSharingStatus.of(true, sharing, true));
        config.setLocalServices(List.of(local));
        return config;
    }

    private static LocalPeerService localService(int targetPort, boolean enabled) {
        LocalPeerService local = new LocalPeerService();
        local.setServiceId("svc-http01");
        local.setName("web");
        local.setTransport("tcp");
        local.setApplication("http");
        local.setTargetHost("127.0.0.1");
        local.setTargetPort(targetPort);
        local.setPublishedPort(18080);
        local.setPath("/app");
        local.setEnabled(enabled);
        return local;
    }

    private static PeerControlMessage catalogMessage() {
        PeerAdvertisedService service = new PeerAdvertisedService();
        service.setServiceId("svc-http01");
        service.setName("web");
        service.setTransport("tcp");
        service.setApplication("http");
        service.setPublishedPort(8080);
        service.setPath("/app");
        PeerControlMessage catalog = new PeerControlMessage();
        catalog.setType(PeerControlMessage.TYPE_SERVICE_CATALOG);
        catalog.setPublisherClientId(2L);
        catalog.setPublisherClientName("client-b");
        catalog.setPublisherSessionId(9L);
        catalog.setRevision(1L);
        catalog.setExpiresAt(Instant.now().plusSeconds(60).toString());
        catalog.setServices(List.of(service));
        return catalog;
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static ServerSocket listen(int port) throws Exception {
        ServerSocket socket = new ServerSocket(port);
        socket.setReuseAddress(true);
        return socket;
    }

    private static void waitUntil(java.util.concurrent.Callable<Boolean> condition) throws Exception {
        for (int i = 0; i < 50; i++) {
            if (Boolean.TRUE.equals(condition.call())) {
                return;
            }
            Thread.sleep(20);
        }
        throw new AssertionError("condition not met");
    }
}
