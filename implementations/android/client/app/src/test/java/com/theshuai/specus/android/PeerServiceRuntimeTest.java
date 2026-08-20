package com.theshuai.specus.android;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Test;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
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
        runtime.applyConfig(config(true, freePort(), false));
        runtime.applyCatalog(catalogJson());
        assertFalse(runtime.remoteServices().get(0).openable);
        assertTrue(runtime.remoteServices().get(0).unavailableReason.contains("离线"));

        JSONObject empty = catalogJson();
        empty.put("revision", 2L);
        empty.put("services", new org.json.JSONArray());
        runtime.applyCatalog(empty);
        assertTrue(runtime.remoteServices().isEmpty());
    }

    @Test
    public void catalogRevisionTombstoneRejectsRollbackAndLateRevival() throws Exception {
        runtime = newRuntime();
        runtime.setRoster(Map.of(2L, new PeerServiceRuntime.RosterHint("100.96.0.2", true)));
        runtime.applyConfig(config(true, freePort(), false));
        runtime.setHasAuthorizedOnlinePeer(true);
        JSONObject current = catalogJson();
        current.put("revision", 2L);
        runtime.applyCatalog(current);

        JSONObject staleWithdrawal = catalogJson();
        staleWithdrawal.put("revision", 1L);
        staleWithdrawal.put("services", new org.json.JSONArray());
        runtime.applyCatalog(staleWithdrawal);
        assertEquals(1, runtime.remoteServices().size());

        JSONObject withdrawal = catalogJson();
        withdrawal.put("revision", 3L);
        withdrawal.put("services", new org.json.JSONArray());
        runtime.applyCatalog(withdrawal);
        runtime.applyCatalog(current);
        assertTrue(runtime.remoteServices().isEmpty());
    }

    @Test
    public void reconnectClearsCatalogRevisionHighWaterAndAcceptsCurrentSnapshot() throws Exception {
        runtime = newRuntime();
        runtime.setRoster(Map.of(2L, new PeerServiceRuntime.RosterHint("100.96.0.2", true)));
        runtime.applyConfig(config(true, freePort(), false));
        runtime.setHasAuthorizedOnlinePeer(true);
        JSONObject current = catalogJson();
        current.put("revision", 7L);
        runtime.applyCatalog(current);
        assertEquals(1, runtime.remoteServices().size());

        runtime.setHasAuthorizedOnlinePeer(false);
        assertTrue(runtime.remoteServices().isEmpty());
        runtime.setHasAuthorizedOnlinePeer(true);
        runtime.applyCatalog(current);

        assertEquals(1, runtime.remoteServices().size());
    }

    @Test
    public void stableCatalogIsRenewedAcrossMultipleLeaseTtls() throws Exception {
        int port = freePort();
        try (ServerSocket ignored = listen(port)) {
            runtime = newRuntime();
            runtime.setHasAuthorizedOnlinePeer(true);
            runtime.applyConfig(config(true, port, true));
            waitUntil(() -> !sent.isEmpty());
            sent.clear();
            runtime.probeAndReport();
            assertTrue(sent.isEmpty());
            for (int elapsedTtls = 1; elapsedTtls <= 3; elapsedTtls++) {
                runtime.forceReportRefreshForTest();
                runtime.probeAndReport();
                assertEquals(elapsedTtls, sent.size());
            }
        }
    }

    @Test
    public void snapshotIncludesServiceIdentityAndDisablesLocalToggleWhenSharingIsOff() throws Exception {
        runtime = newRuntime();
        runtime.setRoster(Map.of(2L, new PeerServiceRuntime.RosterHint("100.96.0.2", true)));
        runtime.applyConfig(config(true, freePort(), false));
        runtime.applyCatalog(catalogJson());

        JSONObject enabled = new JSONObject(PeerServiceRuntime.lastSnapshotJson());
        JSONObject remote = enabled.getJSONArray("remotes").getJSONObject(0);
        assertEquals("svc-http01", remote.getString("serviceId"));
        assertEquals("web", remote.getString("name"));

        runtime.applyConfig(config(false, freePort(), true));
        JSONObject disabled = new JSONObject(PeerServiceRuntime.lastSnapshotJson());
        JSONObject local = disabled.getJSONArray("locals").getJSONObject(0);
        assertFalse(local.getBoolean("canToggle"));
        assertFalse(local.getBoolean("locallyPublished"));
        assertEquals(0, disabled.getJSONArray("remotes").length());
    }

    @Test
    public void expiredCatalogIsPrunedAndSnapshotUpdated() throws Exception {
        runtime = newRuntime();
        runtime.setRoster(Map.of(2L, new PeerServiceRuntime.RosterHint("100.96.0.2", true)));
        runtime.applyConfig(config(true, freePort(), false));
        JSONObject catalog = catalogJson();
        catalog.put("expiresAt", Instant.now().minusSeconds(1).toString());
        runtime.applyCatalog(catalog);

        assertTrue(runtime.pruneExpiredCatalogs(Instant.now()));
        assertTrue(runtime.remoteServices().isEmpty());
    }

    @Test
    public void probeTcpDetectsOpenAndClosedPorts() throws Exception {
        assertFalse(PeerServiceRuntime.isLocalServiceTarget("10.255.255.254"));
        int port = freePort();
        assertFalse(PeerServiceRuntime.probeTcp("127.0.0.1", port, 200));
        try (ServerSocket ignored = listen(port)) {
            assertTrue(PeerServiceRuntime.probeTcp("127.0.0.1", port, 400));
        }
    }

    @Test
    public void tcpBridgeEnforcesServerAuthoredSourceAcl() throws Exception {
        int targetPort = freePort();
        int publishedPort = freePort();
        SpecusCore.LocalPeerService local = new SpecusCore.LocalPeerService();
        local.serviceId = "svc-acl01";
        local.targetHost = "127.0.0.1";
        local.targetPort = targetPort;
        local.publishedPort = publishedPort;
        local.allowedPeerVirtualIps = List.of("127.0.0.2");
        try (ServerSocket target = listen(targetPort);
             PeerServiceBridge bridge = PeerServiceBridge.bind("127.0.0.1", local);
             Socket ignored = new Socket("127.0.0.1", publishedPort)) {
            target.setSoTimeout(250);
            try {
                target.accept().close();
                throw new AssertionError("unauthorized source reached local target");
            } catch (SocketTimeoutException expected) {
                // expected
            }
        }

        publishedPort = freePort();
        local.publishedPort = publishedPort;
        local.allowedPeerVirtualIps = List.of("127.0.0.1");
        try (ServerSocket target = listen(targetPort);
             PeerServiceBridge bridge = PeerServiceBridge.bind("127.0.0.1", local);
             Socket ignored = new Socket("127.0.0.1", publishedPort);
             Socket forwarded = target.accept()) {
            assertTrue(forwarded.isConnected());
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
