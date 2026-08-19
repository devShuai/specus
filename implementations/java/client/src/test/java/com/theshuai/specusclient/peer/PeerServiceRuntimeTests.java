package com.theshuai.specusclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.peermesh.LocalPeerService;
import com.theshuai.common.peermesh.PeerAdvertisedService;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.peermesh.PeerServiceSharingStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
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
        runtime.setRosterLookup(id -> new PeerServiceRuntime.RosterHint("100.96.0.2", false));
        runtime.applyCatalog(catalogMessage());
        assertThat(runtime.remoteServices().getFirst().openable()).isFalse();
        assertThat(runtime.remoteServices().getFirst().unavailableReason()).contains("离线");

        PeerControlMessage empty = catalogMessage();
        empty.setServices(List.of());
        runtime.applyCatalog(empty);
        assertThat(runtime.remoteServices()).isEmpty();
    }

    @Test
    void probeTcpDetectsOpenAndClosedPorts() throws Exception {
        int port = freePort();
        assertThat(PeerServiceDiscovery.probeTcp("127.0.0.1", port, 200)).isFalse();
        try (ServerSocket ignored = listen(port)) {
            assertThat(PeerServiceDiscovery.probeTcp("127.0.0.1", port, 400)).isTrue();
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
