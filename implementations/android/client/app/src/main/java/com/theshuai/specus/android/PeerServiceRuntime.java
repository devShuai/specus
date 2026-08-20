package com.theshuai.specus.android;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

final class PeerServiceRuntime implements AutoCloseable {
    static final int PROBE_TIMEOUT_MILLIS = 400;
    private static final long PROBE_INTERVAL_SECONDS = 15;
    private static final long CATALOG_TTL_SECONDS = 300;
    private static final long REPORT_REFRESH_MILLIS = TimeUnit.SECONDS.toMillis(CATALOG_TTL_SECONDS / 2);
    private static final int MAX_CATALOG_REVISIONS = 4096;

    private static final AtomicReference<String> LAST_SNAPSHOT_JSON = new AtomicReference<>("{\"remotes\":[],\"locals\":[]}");
    private static volatile PeerServiceRuntime active;

    private final Sender sender;
    private final CatalogListener catalogListener;
    private final ScheduledExecutorService scheduler;
    private final boolean ownScheduler;
    private final String instanceId = UUID.randomUUID().toString();
    private final AtomicLong revision = new AtomicLong();
    private final AtomicBoolean hasAuthorizedOnlinePeer = new AtomicBoolean();
    private final Map<CatalogKey, CatalogSnapshot> catalogs = new ConcurrentHashMap<>();
    private final Map<CatalogKey, Long> catalogRevisions = new ConcurrentHashMap<>();
    private final Map<String, AutoCloseable> bridges = new ConcurrentHashMap<>();
    private final Map<String, SpecusCore.LocalPeerService> bridgeLocals = new ConcurrentHashMap<>();
    private final Object lock = new Object();
    private volatile SpecusCore.PeerMeshConfig config = new SpecusCore.PeerMeshConfig();
    private volatile Map<Long, RosterHint> roster = Map.of();
    private volatile ScheduledFuture<?> probeTask;
    private volatile List<String> lastReportedIds = List.of();
    private volatile long lastReportAtMillis;
    private final Set<String> locallyPaused = ConcurrentHashMap.newKeySet();

    PeerServiceRuntime(Sender sender, CatalogListener catalogListener) {
        this(sender, catalogListener, Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "peer-service-runtime");
            thread.setDaemon(true);
            return thread;
        }), true);
    }

    PeerServiceRuntime(Sender sender, CatalogListener catalogListener, ScheduledExecutorService scheduler) {
        this(sender, catalogListener, scheduler, false);
    }

    private PeerServiceRuntime(Sender sender, CatalogListener catalogListener,
                               ScheduledExecutorService scheduler, boolean ownScheduler) {
        this.sender = sender;
        this.catalogListener = catalogListener;
        this.scheduler = scheduler;
        this.ownScheduler = ownScheduler;
        active = this;
    }

    static String lastSnapshotJson() {
        return LAST_SNAPSHOT_JSON.get();
    }

    void applyConfig(SpecusCore.PeerMeshConfig next) {
        synchronized (lock) {
            this.config = next == null ? new SpecusCore.PeerMeshConfig() : next;
            if (!effectiveSharing()) {
                stopProbeLocked();
                closeBridges();
                catalogs.clear();
                catalogRevisions.clear();
                publishSnapshot();
                if (!lastReportedIds.isEmpty() || revision.get() > 0) {
                    sendWithdrawLocked();
                }
                return;
            }
            reconcileBridgesLocked();
            scheduleProbeLocked();
        }
        probeAndReport();
        publishSnapshot();
    }

    void setHasAuthorizedOnlinePeer(boolean onlinePeer) {
        boolean previous = hasAuthorizedOnlinePeer.getAndSet(onlinePeer);
        if (previous == onlinePeer) {
            return;
        }
        synchronized (lock) {
            if (!effectiveSharing() || !onlinePeer) {
                stopProbeLocked();
                closeBridges();
                catalogs.clear();
                catalogRevisions.clear();
                publishSnapshot();
                return;
            }
            reconcileBridgesLocked();
            scheduleProbeLocked();
        }
        probeAndReport();
    }

    void setRoster(Map<Long, RosterHint> next) {
        roster = next == null ? Map.of() : Map.copyOf(next);
        publishSnapshot();
    }

    void applyCatalog(JSONObject catalog) {
        if (catalog == null || !effectiveSharing()) {
            return;
        }
        long publisherClientId = catalog.optLong("publisherClientId", 0L);
        long publisherSessionId = catalog.optLong("publisherSessionId", 0L);
        if (publisherClientId <= 0 || publisherSessionId <= 0) {
            return;
        }
        CatalogKey key = new CatalogKey(publisherClientId, publisherSessionId);
        long catalogRevision = catalog.optLong("revision", 0L);
        if (catalogRevision < 1 || !acceptCatalogRevision(key, catalogRevision)) {
            return;
        }
        List<AdvertisedService> services = parseServices(catalog.optJSONArray("services"));
        if (services.isEmpty()) {
            catalogs.remove(key);
            publishSnapshot();
            return;
        }
        Instant expiresAt = parseInstant(catalog.optString("expiresAt", ""),
                Instant.now().plusSeconds(CATALOG_TTL_SECONDS));
        catalogs.put(key, new CatalogSnapshot(
                publisherClientId,
                catalog.optString("publisherClientName", ""),
                publisherSessionId,
                catalogRevision,
                expiresAt,
                services));
        publishSnapshot();
    }

    List<RemoteServiceView> remoteServices() {
        Instant now = Instant.now();
        List<RemoteServiceView> views = new ArrayList<>();
        Map<Long, RosterHint> hints = roster;
        for (CatalogSnapshot snapshot : catalogs.values()) {
            if (snapshot.expiresAt.isBefore(now)) {
                continue;
            }
            RosterHint hint = hints.getOrDefault(snapshot.publisherClientId, RosterHint.unknown());
            for (AdvertisedService service : snapshot.services) {
                views.add(RemoteServiceView.from(snapshot, hint, service));
            }
        }
        return List.copyOf(views);
    }

    boolean effectiveSharing() {
        return config != null && config.serviceSharing != null && config.serviceSharing.effectiveEnabled;
    }

    void setLocalPublished(String serviceId, boolean published) {
        if (serviceId == null || serviceId.isBlank()) {
            return;
        }
        if (published) {
            locallyPaused.remove(serviceId.trim());
        } else {
            locallyPaused.add(serviceId.trim());
        }
        probeAndReport();
        publishSnapshot();
    }

    boolean isLocallyPublished(String serviceId) {
        return serviceId == null || !locallyPaused.contains(serviceId);
    }

    void probeAndReport() {
        boolean catalogChanged = pruneExpiredCatalogs(Instant.now());
        if (catalogChanged) {
            publishSnapshot();
        }
        synchronized (lock) {
            if (!effectiveSharing() || !hasAuthorizedOnlinePeer.get()) {
                closeBridges();
                return;
            }
            List<AdvertisedService> reachable = new ArrayList<>();
            for (SpecusCore.LocalPeerService local : enabledLocals()) {
                if (!probe(local, PROBE_TIMEOUT_MILLIS)) {
                    continue;
                }
                reachable.add(advertised(local));
            }
            List<String> ids = new ArrayList<>();
            for (AdvertisedService service : reachable) {
                ids.add(service.serviceId);
            }
            if (ids.equals(lastReportedIds) && revision.get() > 0
                    && System.currentTimeMillis() - lastReportAtMillis < REPORT_REFRESH_MILLIS) {
                reconcileBridgesLocked();
                return;
            }
            lastReportedIds = ids;
            sendReportLocked(true, reachable);
            reconcileBridgesLocked();
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            stopProbeLocked();
            closeBridges();
            catalogs.clear();
            catalogRevisions.clear();
            publishSnapshot();
        }
        if (ownScheduler) {
            scheduler.shutdownNow();
        }
        if (active == this) {
            active = null;
        }
    }

    void forceReportRefreshForTest() {
        lastReportAtMillis = 0L;
    }

    private boolean acceptCatalogRevision(CatalogKey key, long next) {
        if (!catalogRevisions.containsKey(key) && catalogRevisions.size() >= MAX_CATALOG_REVISIONS) {
            return false;
        }
        for (;;) {
            Long current = catalogRevisions.get(key);
            if (current == null) {
                if (catalogRevisions.putIfAbsent(key, next) == null) {
                    return true;
                }
                continue;
            }
            if (next <= current) {
                return false;
            }
            if (catalogRevisions.replace(key, current, next)) {
                return true;
            }
        }
    }

    static void setActiveLocalPublished(String serviceId, boolean published) {
        PeerServiceRuntime runtime = active;
        if (runtime != null) {
            runtime.setLocalPublished(serviceId, published);
        }
    }

    static boolean probe(SpecusCore.LocalPeerService local, int timeoutMillis) {
        if (local == null || !isLocalServiceTarget(local.targetHost)) {
            return false;
        }
        if ("udp".equalsIgnoreCase(local.transport) || "udp".equalsIgnoreCase(local.application)) {
            return probeUdp(local.targetHost, local.targetPort, timeoutMillis);
        }
        return probeTcp(local.targetHost, local.targetPort, timeoutMillis);
    }

    static boolean probeTcp(String host, int port, int timeoutMillis) {
        if (!isLocalServiceTarget(host) || port < 1 || port > 65535) {
            return false;
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), Math.max(50, timeoutMillis));
            return socket.isConnected();
        } catch (Exception ignored) {
            return false;
        }
    }

    static boolean probeUdp(String host, int port, int timeoutMillis) {
        if (!isLocalServiceTarget(host) || port < 1 || port > 65535) {
            return false;
        }
        try (java.net.DatagramSocket socket = new java.net.DatagramSocket()) {
            socket.setSoTimeout(Math.max(50, timeoutMillis));
            socket.connect(new InetSocketAddress(host, port));
            socket.send(new java.net.DatagramPacket(new byte[]{0}, 1));
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    static boolean isLocalServiceTarget(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        try {
            InetAddress address = InetAddress.getByName(host.trim());
            return address.isLoopbackAddress() || NetworkInterface.getByInetAddress(address) != null;
        } catch (Exception ignored) {
            return false;
        }
    }

    static String accessUrl(String virtualIp, AdvertisedService service) {
        if (virtualIp == null || virtualIp.isBlank() || service == null) {
            return "";
        }
        if ("http".equals(service.application) || "https".equals(service.application)) {
            String path = service.path == null || service.path.isBlank() ? "/" : service.path;
            return service.application + "://" + virtualIp + ":" + service.publishedPort + path;
        }
        return virtualIp + ":" + service.publishedPort;
    }

    private void reconcileBridgesLocked() {
        if (!effectiveSharing() || !hasAuthorizedOnlinePeer.get()
                || config.virtualIp == null || config.virtualIp.isBlank()) {
            closeBridges();
            return;
        }
        Map<String, SpecusCore.LocalPeerService> desired = new LinkedHashMap<>();
        for (SpecusCore.LocalPeerService local : enabledLocals()) {
            if (probe(local, PROBE_TIMEOUT_MILLIS)) {
                desired.put(local.serviceId, local);
            }
        }
        for (String id : new ArrayList<>(bridges.keySet())) {
            if (!desired.containsKey(id)) {
                closeQuietly(bridges.remove(id));
                bridgeLocals.remove(id);
            }
        }
        for (SpecusCore.LocalPeerService local : desired.values()) {
            SpecusCore.LocalPeerService bound = bridgeLocals.get(local.serviceId);
            if (bound != null && matches(config.virtualIp, bound, local)) {
                continue;
            }
            closeQuietly(bridges.remove(local.serviceId));
            try {
                AutoCloseable forwarder = isUdp(local)
                        ? PeerServiceUdpBridge.bind(config.virtualIp, local)
                        : PeerServiceBridge.bind(config.virtualIp, local);
                bridges.put(local.serviceId, forwarder);
                bridgeLocals.put(local.serviceId, local);
            } catch (Exception ignored) {
            }
        }
    }

    private static boolean isUdp(SpecusCore.LocalPeerService local) {
        return "udp".equalsIgnoreCase(local.transport) || "udp".equalsIgnoreCase(local.application);
    }

    private boolean matches(String virtualIp, SpecusCore.LocalPeerService current, SpecusCore.LocalPeerService next) {
        return Objects.equals(current.serviceId, next.serviceId)
                && current.publishedPort == next.publishedPort
                && Objects.equals(current.targetHost, next.targetHost)
                && current.targetPort == next.targetPort
                && PeerServiceBridge.allowedPeerAddresses(current)
                .equals(PeerServiceBridge.allowedPeerAddresses(next))
                && Objects.equals(config.virtualIp, virtualIp);
    }

    private static void closeQuietly(AutoCloseable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (Exception ignored) {
        }
    }

    private List<SpecusCore.LocalPeerService> enabledLocals() {
        List<SpecusCore.LocalPeerService> locals = config.localServices;
        if (locals == null || locals.isEmpty()) {
            return List.of();
        }
        List<SpecusCore.LocalPeerService> enabled = new ArrayList<>();
        for (SpecusCore.LocalPeerService local : locals) {
            if (local != null && local.enabled && !locallyPaused.contains(local.serviceId)) {
                enabled.add(local);
            }
        }
        return enabled;
    }

    private void scheduleProbeLocked() {
        stopProbeLocked();
        probeTask = scheduler.scheduleAtFixedRate(this::probeAndReport,
                PROBE_INTERVAL_SECONDS, PROBE_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }

    private void stopProbeLocked() {
        ScheduledFuture<?> task = probeTask;
        probeTask = null;
        if (task != null) {
            task.cancel(false);
        }
    }

    private void sendReportLocked(boolean enabled, List<AdvertisedService> services) {
        try {
            lastReportAtMillis = System.currentTimeMillis();
            JSONObject report = new JSONObject();
            report.put("type", "service-report");
            report.put("enabled", enabled);
            report.put("revision", revision.incrementAndGet());
            report.put("instanceId", instanceId);
            report.put("generatedAt", Instant.now().toString());
            report.put("expiresAt", Instant.now().plusSeconds(CATALOG_TTL_SECONDS).toString());
            report.put("createdAtMillis", System.currentTimeMillis());
            JSONArray array = new JSONArray();
            for (AdvertisedService service : services) {
                array.put(service.toJson());
            }
            report.put("services", array);
            sender.send("", report.toString());
        } catch (Exception ignored) {
        }
    }

    private void sendWithdrawLocked() {
        lastReportedIds = List.of();
        sendReportLocked(false, List.of());
    }

    private void closeBridges() {
        for (AutoCloseable bridge : bridges.values()) {
            closeQuietly(bridge);
        }
        bridges.clear();
        bridgeLocals.clear();
    }

    private void publishSnapshot() {
        JSONObject root = new JSONObject();
        JSONArray remotes = new JSONArray();
        JSONArray locals = new JSONArray();
        try {
            for (RemoteServiceView view : remoteServices()) {
                remotes.put(view.toJson());
            }
            List<SpecusCore.LocalPeerService> configured = config.localServices == null
                    ? List.of() : config.localServices;
            for (SpecusCore.LocalPeerService local : configured) {
                if (local == null) {
                    continue;
                }
                JSONObject item = new JSONObject();
                item.put("serviceId", local.serviceId);
                item.put("name", local.name);
                item.put("application", local.application);
                item.put("target", local.targetHost + ":" + local.targetPort);
                item.put("publishedPort", local.publishedPort);
                item.put("configEnabled", local.enabled);
                item.put("canToggle", effectiveSharing() && local.enabled);
                item.put("locallyPublished", effectiveSharing() && local.enabled
                        && isLocallyPublished(local.serviceId));
                locals.put(item);
            }
            root.put("remotes", remotes);
            root.put("locals", locals);
        } catch (Exception ignored) {
        }
        String json = root.toString();
        LAST_SNAPSHOT_JSON.set(json);
        if (catalogListener != null) {
            catalogListener.onCatalogChanged(json);
        }
    }

    boolean pruneExpiredCatalogs(Instant now) {
        boolean changed = false;
        for (Map.Entry<CatalogKey, CatalogSnapshot> entry : catalogs.entrySet()) {
            CatalogSnapshot snapshot = entry.getValue();
            if (!snapshot.expiresAt.isAfter(now) && catalogs.remove(entry.getKey(), snapshot)) {
                changed = true;
            }
        }
        return changed;
    }

    private static AdvertisedService advertised(SpecusCore.LocalPeerService local) {
        AdvertisedService service = new AdvertisedService();
        service.serviceId = local.serviceId;
        service.name = local.name;
        service.description = local.description;
        service.transport = local.transport;
        service.application = local.application;
        service.publishedPort = local.publishedPort;
        service.path = local.path;
        return service;
    }

    private static List<AdvertisedService> parseServices(JSONArray array) {
        List<AdvertisedService> services = new ArrayList<>();
        if (array == null) {
            return services;
        }
        for (int i = 0; i < array.length(); i++) {
            JSONObject item = array.optJSONObject(i);
            if (item == null) {
                continue;
            }
            AdvertisedService service = new AdvertisedService();
            service.serviceId = item.optString("serviceId", "");
            service.name = item.optString("name", "");
            service.description = item.optString("description", "");
            service.transport = item.optString("transport", "tcp");
            service.application = item.optString("application", "tcp");
            service.publishedPort = item.optInt("publishedPort", 0);
            service.path = item.optString("path", "");
            services.add(service);
        }
        return services;
    }

    private static Instant parseInstant(String raw, Instant fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Instant.parse(raw.trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    interface Sender {
        void send(String toClientName, String message) throws Exception;
    }

    interface CatalogListener {
        void onCatalogChanged(String json);
    }

    static final class RosterHint {
        final String virtualIp;
        final boolean online;

        RosterHint(String virtualIp, boolean online) {
            this.virtualIp = virtualIp == null ? "" : virtualIp;
            this.online = online;
        }

        static RosterHint unknown() {
            return new RosterHint("", false);
        }
    }

    static final class CatalogKey {
        final long publisherClientId;
        final long publisherSessionId;

        CatalogKey(long publisherClientId, long publisherSessionId) {
            this.publisherClientId = publisherClientId;
            this.publisherSessionId = publisherSessionId;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof CatalogKey key)) {
                return false;
            }
            return publisherClientId == key.publisherClientId && publisherSessionId == key.publisherSessionId;
        }

        @Override
        public int hashCode() {
            return Objects.hash(publisherClientId, publisherSessionId);
        }
    }

    static final class CatalogSnapshot {
        final long publisherClientId;
        final String publisherClientName;
        final long publisherSessionId;
        final long revision;
        final Instant expiresAt;
        final List<AdvertisedService> services;

        CatalogSnapshot(long publisherClientId, String publisherClientName, long publisherSessionId,
                        long revision, Instant expiresAt, List<AdvertisedService> services) {
            this.publisherClientId = publisherClientId;
            this.publisherClientName = publisherClientName;
            this.publisherSessionId = publisherSessionId;
            this.revision = revision;
            this.expiresAt = expiresAt;
            this.services = services;
        }
    }

    static final class AdvertisedService {
        String serviceId;
        String name;
        String description;
        String transport;
        String application;
        int publishedPort;
        String path;

        JSONObject toJson() throws Exception {
            JSONObject json = new JSONObject();
            json.put("serviceId", serviceId);
            json.put("name", name);
            json.put("description", description);
            json.put("transport", transport);
            json.put("application", application);
            json.put("publishedPort", publishedPort);
            json.put("path", path);
            return json;
        }
    }

    static final class RemoteServiceView {
        final long publisherClientId;
        final String publisherClientName;
        final long publisherSessionId;
        final String virtualIp;
        final boolean publisherOnline;
        final boolean fresh;
        final AdvertisedService service;
        final String accessTarget;
        final boolean openable;
        final boolean copyable;
        final String unavailableReason;

        RemoteServiceView(long publisherClientId, String publisherClientName, long publisherSessionId,
                          String virtualIp, boolean publisherOnline, boolean fresh, AdvertisedService service,
                          String accessTarget, boolean openable, boolean copyable, String unavailableReason) {
            this.publisherClientId = publisherClientId;
            this.publisherClientName = publisherClientName;
            this.publisherSessionId = publisherSessionId;
            this.virtualIp = virtualIp;
            this.publisherOnline = publisherOnline;
            this.fresh = fresh;
            this.service = service;
            this.accessTarget = accessTarget;
            this.openable = openable;
            this.copyable = copyable;
            this.unavailableReason = unavailableReason;
        }

        static RemoteServiceView from(CatalogSnapshot snapshot, RosterHint hint, AdvertisedService service) {
            boolean http = "http".equals(service.application) || "https".equals(service.application);
            boolean fresh = snapshot.expiresAt.isAfter(Instant.now());
            String virtualIp = hint.virtualIp;
            String reason = !fresh ? "目录已过期"
                    : !hint.online ? "发布端离线"
                    : virtualIp.isBlank() ? "缺少虚拟 IP"
                    : "";
            return new RemoteServiceView(
                    snapshot.publisherClientId,
                    snapshot.publisherClientName,
                    snapshot.publisherSessionId,
                    virtualIp,
                    hint.online,
                    fresh,
                    service,
                    virtualIp.isBlank() ? "" : accessUrl(virtualIp, service),
                    http && reason.isEmpty(),
                    !http && reason.isEmpty(),
                    reason);
        }

        JSONObject toJson() throws Exception {
            JSONObject json = new JSONObject();
            json.put("publisherClientId", publisherClientId);
            json.put("publisherClientName", publisherClientName);
            json.put("publisherSessionId", publisherSessionId);
            json.put("serviceId", service.serviceId);
            json.put("name", service.name);
            json.put("application", service.application);
            json.put("accessTarget", accessTarget);
            json.put("openable", openable);
            json.put("copyable", copyable);
            json.put("unavailableReason", unavailableReason);
            return json;
        }
    }
}
