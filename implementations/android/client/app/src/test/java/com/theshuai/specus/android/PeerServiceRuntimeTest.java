package com.theshuai.specus.android;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Test;

import java.net.ServerSocket;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PeerServiceRuntimeTest {
    private final List<String> sent = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private PeerServiceRuntime runtime;

    @After
    public void tearDown() {
        if (runtime != null) {
            runtime.close();
        }
        scheduler.shutdownNow();
    }

    @Test
    public void doesNotProbeOrReportWhenSharingIsOff() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setHasAuthorizedOnlinePeer(true);
            runtime.applyConfig(config(false, port, true));
            Thread.sleep(50);
            assertTrue(sent.isEmpty());
        }
    }

    @Test
    public void doesNotProbeWithoutAuthorizedOnlinePeer() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setHasAuthorizedOnlinePeer(false);
            runtime.applyConfig(config(true, port, true));
            Thread.sleep(50);
            assertTrue(sent.isEmpty());
        }
    }

    @Test
    public void reportsReachableServiceAndBuildsSafeCatalogUrl() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setRoster(Map.of(2L, new PeerServiceRuntime.RosterHint("100.96.0.2", true)));
            runtime.setHasAuthorizedOnlinePeer(true);
            runtime.applyConfig(config(true, port, true));
            waitUntil(() -> !sent.isEmpty());
            assertTrue(sent.get(0).contains("service-report"));
            assertTrue(sent.get(0).contains("svc-http01"));
            assertFalse(sent.get(0).contains("targetHost"));

            runtime.applyCatalog(catalogJson());
            List<PeerServiceRuntime.RemoteServiceView> views = runtime.remoteServices();
            assertEquals(1, views.size());
            assertTrue(views.get(0).openable);
            assertEquals("http://100.96.0.2:8080/app", views.get(0).accessTarget);
            assertFalse(views.get(0).accessTarget.contains("evil"));
        }
    }

    @Test
    public void emptyCatalogWithdrawsAndOfflinePublisherDisablesOpen() throws Exception {
        runtime = newRuntime();
        runtime.setRoster(Map.of(2L, new PeerServiceRuntime.RosterHint("100.96.0.2", false)));
        runtime.applyCatalog(catalogJson());
        assertFalse(runtime.remoteServices().get(0).openable);
        assertTrue(runtime.remoteServices().get(0).unavailableReason.contains("离线"));

        JSONObject empty = catalogJson();
        empty.put("services", new org.json.JSONArray());
        runtime.applyCatalog(empty);
        assertTrue(runtime.remoteServices().isEmpty());
    }

    @Test
    public void probeTcpDetectsOpenAndClosedPorts() throws Exception {
        int port = freePort();
        assertFalse(PeerServiceRuntime.probeTcp("127.0.0.1", port, 200));
        try (ServerSocket ignored = listen(port)) {
            assertTrue(PeerServiceRuntime.probeTcp("127.0.0.1", port, 400));
        }
    }

    private PeerServiceRuntime newRuntime() {
        return new PeerServiceRuntime((to, message) -> sent.add(message), ignored -> {
        }, scheduler);
    }

    private static SpecusCore.PeerMeshConfig config(boolean sharing, int targetPort, boolean enabled) {
        SpecusCore.PeerMeshConfig config = new SpecusCore.PeerMeshConfig();
        config.enabled = true;
        config.virtualIp = "127.0.0.1";
        config.serviceSharing = new SpecusCore.ServiceSharingStatus();
        config.serviceSharing.deploymentEnabled = true;
        config.serviceSharing.configuredEnabled = sharing;
        config.serviceSharing.effectiveEnabled = sharing;
        SpecusCore.LocalPeerService local = new SpecusCore.LocalPeerService();
        local.serviceId = "svc-http01";
        local.name = "web";
        local.transport = "tcp";
        local.application = "http";
        local.targetHost = "127.0.0.1";
        local.targetPort = targetPort;
        local.publishedPort = 18080;
        local.path = "/app";
        local.enabled = enabled;
        config.localServices = List.of(local);
        return config;
    }

    private static JSONObject catalogJson() throws Exception {
        JSONObject service = new JSONObject();
        service.put("serviceId", "svc-http01");
        service.put("name", "web");
        service.put("transport", "tcp");
        service.put("application", "http");
        service.put("publishedPort", 8080);
        service.put("path", "/app");
        JSONObject catalog = new JSONObject();
        catalog.put("type", "service-catalog");
        catalog.put("publisherClientId", 2L);
        catalog.put("publisherClientName", "client-b");
        catalog.put("publisherSessionId", 9L);
        catalog.put("revision", 1L);
        catalog.put("expiresAt", Instant.now().plusSeconds(60).toString());
        catalog.put("services", new org.json.JSONArray().put(service));
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
