package com.theshuai.specus.android;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
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
            SpecusCore.PeerMeshConfig config = config(true, port, true);
            config.localServices.get(0).serviceId = "svc-wire01";
            config.localServices.get(0).name = "fixture-http";
            config.localServices.get(0).description = "wire fixture";
            config.localServices.get(0).path = "/health";
            runtime.applyConfig(config);
            waitUntil(() -> !sent.isEmpty());
            assertTrue(sent.get(0).contains("service-report"));
            assertTrue(sent.get(0).contains("svc-wire01"));
            assertFalse(sent.get(0).contains("targetHost"));
            JSONObject vectors = ProtocolVectorTestSupport.read("peer-service-discovery-v2.json");
            JSONObject actualReport = new JSONObject(sent.get(0));
            JSONObject expectedReport = vectors.getJSONObject("serviceReports").getJSONObject("android");
            for (String dynamic : List.of(
                    "revision", "instanceId", "generatedAt", "expiresAt", "createdAtMillis")) {
                expectedReport.put(dynamic, actualReport.get(dynamic));
            }
            assertEquals(canonical(expectedReport), canonical(actualReport));

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
    public void clientCapabilitiesMatchTheSharedWireFixture() throws Exception {
        JSONObject vectors = ProtocolVectorTestSupport.read("peer-service-discovery-v2.json");
        SpecusCore.ClientPeerServiceCapabilities capabilities =
                SpecusCore.ClientPeerServiceCapabilities.androidDefault();
        assertEquals(vectors.getInt("protocolVersion"), capabilities.version);
        org.json.JSONArray applications = vectors.getJSONArray("applications");
        assertEquals(applications.length(), capabilities.applications.size());
        for (int index = 0; index < applications.length(); index++) {
            assertEquals(applications.getString(index), capabilities.applications.get(index));
        }
    }

    @Test
    public void catalogWithFutureFieldRemainsCompatible() throws Exception {
        runtime = newRuntime();
        runtime.setRoster(Map.of(10L, new PeerServiceRuntime.RosterHint("100.96.0.10", true)));
        runtime.applyConfig(config(true, freePort(), false));
        runtime.setHasAuthorizedOnlinePeer(true);
        JSONObject vectors = ProtocolVectorTestSupport.read("peer-service-discovery-v2.json");

        runtime.applyCatalog(vectors.getJSONObject("legacyCompatibility")
                .getJSONObject("catalogWithFutureField"));

        assertTrue(runtime.remoteServices().isEmpty());
    }

    @Test
    public void onlineConfigCreatesReplacesAndClosesBridgeWithinFiveSeconds() throws Exception {
        int firstPublishedPort = freePort();
        int secondPublishedPort = freePort();
        try (ServerSocket firstTarget = listen(freePort());
             ServerSocket secondTarget = listen(freePort())) {
            firstTarget.setSoTimeout(5_000);
            secondTarget.setSoTimeout(5_000);
            runtime = newRuntime();
            runtime.setHasAuthorizedOnlinePeer(true);

            SpecusCore.PeerMeshConfig first = config(true, firstTarget.getLocalPort(), true);
            first.localServices.get(0).publishedPort = firstPublishedPort;
            first.localServices.get(0).allowedPeerVirtualIps = List.of("127.0.0.1");
            long started = System.nanoTime();
            runtime.applyConfig(first);
            try (Socket firstCaller = new Socket("127.0.0.1", firstPublishedPort);
                 Socket firstForwarded = firstTarget.accept()) {
                assertTrue(java.time.Duration.ofNanos(System.nanoTime() - started).compareTo(
                        java.time.Duration.ofSeconds(5)) < 0);

                SpecusCore.PeerMeshConfig replacement = config(true, secondTarget.getLocalPort(), true);
                replacement.localServices.get(0).publishedPort = secondPublishedPort;
                replacement.localServices.get(0).allowedPeerVirtualIps = List.of("127.0.0.1");
                runtime.applyConfig(replacement);
                firstCaller.setSoTimeout(1_000);
                assertTrue(readClosed(firstCaller));
                assertConnectRejected(firstPublishedPort);

                try (Socket secondCaller = new Socket("127.0.0.1", secondPublishedPort);
                     Socket secondForwarded = secondTarget.accept()) {
                    assertTrue(secondForwarded.isConnected());
                    replacement.localServices.get(0).enabled = false;
                    runtime.applyConfig(replacement);
                    secondCaller.setSoTimeout(1_000);
                    assertTrue(readClosed(secondCaller));
                }
                assertConnectRejected(secondPublishedPort);
            }
        }
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

    @Test
    public void tcpBridgeSeparatesThreePeersAndRevocationClosesTheActiveFlow() throws Exception {
        int targetPort = freePort();
        int publishedPort = freePort();
        SpecusCore.LocalPeerService local = new SpecusCore.LocalPeerService();
        local.serviceId = "svc-acl-three";
        local.targetHost = "127.0.0.1";
        local.targetPort = targetPort;
        local.publishedPort = publishedPort;
        local.allowedPeerVirtualIps = List.of("127.0.0.2");
        try (ServerSocket target = listen(targetPort);
             PeerServiceBridge bridge = PeerServiceBridge.bind("127.0.0.1", local);
             Socket denied = connectFrom("127.0.0.3", publishedPort)) {
            target.setSoTimeout(250);
            try {
                target.accept().close();
                throw new AssertionError("peer C bypassed the service ACL");
            } catch (SocketTimeoutException expected) {
                // expected
            }

            try (Socket allowed = connectFrom("127.0.0.2", publishedPort)) {
                target.setSoTimeout(1_000);
                try (Socket forwarded = target.accept()) {
                    assertTrue(forwarded.isConnected());
                    allowed.setSoTimeout(1_000);
                    bridge.close();
                    int result;
                    try {
                        result = allowed.getInputStream().read();
                    } catch (IOException closed) {
                        result = -1;
                    }
                    assertEquals(-1, result);
                }
            }
            boolean reconnectRejected = false;
            try (Socket ignored = connectFrom("127.0.0.2", publishedPort)) {
                // unexpected
            } catch (IOException expected) {
                reconnectRejected = true;
            }
            assertTrue(reconnectRejected);
        }
    }

    @Test
    public void udpBridgeAppliesTheSameAclAndRevocationBoundary() throws Exception {
        byte[] payload = {1, 2, 3};
        try (DatagramSocket target = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             DatagramSocket denied = new DatagramSocket(new InetSocketAddress("127.0.0.3", 0));
             DatagramSocket allowed = new DatagramSocket(new InetSocketAddress("127.0.0.2", 0))) {
            int publishedPort = freeUdpPort();
            SpecusCore.LocalPeerService local = new SpecusCore.LocalPeerService();
            local.serviceId = "svc-udp-acl";
            local.transport = "udp";
            local.application = "udp";
            local.targetHost = "127.0.0.1";
            local.targetPort = target.getLocalPort();
            local.publishedPort = publishedPort;
            local.allowedPeerVirtualIps = List.of("127.0.0.2");
            try (PeerServiceUdpBridge bridge = PeerServiceUdpBridge.bind("127.0.0.1", local)) {
                denied.send(new DatagramPacket(payload, payload.length,
                        new InetSocketAddress("127.0.0.1", publishedPort)));
                target.setSoTimeout(250);
                try {
                    target.receive(new DatagramPacket(new byte[8], 8));
                    throw new AssertionError("unauthorized UDP peer reached the local target");
                } catch (SocketTimeoutException expected) {
                    // expected
                }

                allowed.send(new DatagramPacket(payload, payload.length,
                        new InetSocketAddress("127.0.0.1", publishedPort)));
                target.setSoTimeout(1_000);
                DatagramPacket forwarded = new DatagramPacket(new byte[8], 8);
                target.receive(forwarded);
                assertEquals(payload.length, forwarded.getLength());

                bridge.close();
                allowed.send(new DatagramPacket(payload, payload.length,
                        new InetSocketAddress("127.0.0.1", publishedPort)));
                target.setSoTimeout(250);
                try {
                    target.receive(new DatagramPacket(new byte[8], 8));
                    throw new AssertionError("revoked UDP peer remained forwarded");
                } catch (SocketTimeoutException expected) {
                    // expected
                }
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

    private static boolean readClosed(Socket socket) {
        try {
            return socket.getInputStream().read() == -1;
        } catch (IOException closed) {
            return true;
        }
    }

    private static void assertConnectRejected(int port) throws Exception {
        try (Socket ignored = new Socket("127.0.0.1", port)) {
            throw new AssertionError("closed peer service accepted a new connection");
        } catch (IOException expected) {
            // expected
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

    private static Set<String> jsonKeys(JSONObject object) {
        Set<String> keys = new TreeSet<>();
        object.keys().forEachRemaining(keys::add);
        return keys;
    }

    private static String canonical(Object value) throws Exception {
        if (value instanceof JSONObject object) {
            StringBuilder result = new StringBuilder("{");
            boolean first = true;
            for (String key : jsonKeys(object)) {
                if (!first) {
                    result.append(',');
                }
                first = false;
                result.append(JSONObject.quote(key)).append(':').append(canonical(object.get(key)));
            }
            return result.append('}').toString();
        }
        if (value instanceof org.json.JSONArray array) {
            StringBuilder result = new StringBuilder("[");
            for (int index = 0; index < array.length(); index++) {
                if (index > 0) {
                    result.append(',');
                }
                result.append(canonical(array.get(index)));
            }
            return result.append(']').toString();
        }
        if (value == null || value == JSONObject.NULL) {
            return "null";
        }
        if (value instanceof String text) {
            return JSONObject.quote(text);
        }
        return String.valueOf(value);
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
