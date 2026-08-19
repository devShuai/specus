package com.theshuai.specusclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.peermesh.LocalPeerService;
import com.theshuai.common.peermesh.PeerAdvertisedService;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerMdnsBrowser;
import com.theshuai.common.peermesh.PeerMdnsCandidate;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.peermesh.PeerServiceSharingStatus;
import com.theshuai.common.peermesh.PeerServiceStats;
import com.theshuai.common.util.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.time.Duration;
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
import java.util.function.Function;

/**
 * Client-side Peer service discovery: probe configured local targets, advertise reachable
 * services, consume catalogs, and bind Peer-only TCP bridges on the virtual IP.
 */
@Slf4j
public final class PeerServiceRuntime implements AutoCloseable {
    static final int PROBE_TIMEOUT_MILLIS = 400;
    private static final long PROBE_INTERVAL_SECONDS = 15;

    private final PeerMeshClient.ControlSender sender;
    private final ScheduledExecutorService scheduler;
    private final boolean ownScheduler;
    private final String instanceId = UUID.randomUUID().toString();
    private final AtomicLong revision = new AtomicLong();
    private final AtomicBoolean hasAuthorizedOnlinePeer = new AtomicBoolean();
    private final Map<CatalogKey, CatalogSnapshot> catalogs = new ConcurrentHashMap<>();
    private final Map<String, PeerServiceForwarder> bridges = new ConcurrentHashMap<>();
    private final Object lock = new Object();
    private volatile ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
    private volatile Function<Long, RosterHint> rosterLookup = ignored -> RosterHint.unknown();
    private volatile ScheduledFuture<?> probeTask;
    private volatile List<String> lastReportedIds = List.of();
    private volatile List<PeerServiceStats> lastReportedStats = List.of();
    private volatile List<String> lastMdnsKeys = List.of();
    private final Set<String> locallyPaused = ConcurrentHashMap.newKeySet();

    public PeerServiceRuntime(PeerMeshClient.ControlSender sender) {
        this(sender, Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "peer-service-runtime");
            thread.setDaemon(true);
            return thread;
        }), true);
    }

    PeerServiceRuntime(PeerMeshClient.ControlSender sender, ScheduledExecutorService scheduler) {
        this(sender, scheduler, false);
    }

    private PeerServiceRuntime(PeerMeshClient.ControlSender sender,
                               ScheduledExecutorService scheduler,
                               boolean ownScheduler) {
        this.sender = sender;
        this.scheduler = scheduler;
        this.ownScheduler = ownScheduler;
    }

    public void setRosterLookup(Function<Long, RosterHint> rosterLookup) {
        this.rosterLookup = rosterLookup == null ? ignored -> RosterHint.unknown() : rosterLookup;
    }

    public void applyConfig(ClientAuthLoginResponse.PeerMeshConfig next) {
        synchronized (lock) {
            this.config = next == null ? new ClientAuthLoginResponse.PeerMeshConfig() : next;
            if (!effectiveSharing()) {
                stopProbeLocked();
                closeBridges();
                catalogs.clear();
                if (!lastReportedIds.isEmpty() || revision.get() > 0) {
                    sendWithdrawLocked();
                }
                return;
            }
            reconcileBridgesLocked();
            scheduleProbeLocked();
        }
        probeAndReport();
    }

    public void setHasAuthorizedOnlinePeer(boolean onlinePeer) {
        boolean previous = hasAuthorizedOnlinePeer.getAndSet(onlinePeer);
        if (previous == onlinePeer) {
            return;
        }
        synchronized (lock) {
            if (!effectiveSharing() || !onlinePeer) {
                stopProbeLocked();
                closeBridges();
                return;
            }
            reconcileBridgesLocked();
            scheduleProbeLocked();
        }
        probeAndReport();
    }

    public void applyCatalog(PeerControlMessage catalog) {
        if (catalog == null || catalog.getPublisherClientId() == null || catalog.getPublisherSessionId() == null) {
            return;
        }
        CatalogKey key = new CatalogKey(catalog.getPublisherClientId(), catalog.getPublisherSessionId());
        List<PeerAdvertisedService> services = catalog.getServices() == null
                ? List.of()
                : catalog.getServices().stream().map(PeerServiceDiscovery::copyAdvertised).toList();
        if (services.isEmpty()) {
            catalogs.remove(key);
            log.info("Peer 服务目录已撤回: publisher={} session={}",
                    catalog.getPublisherClientName(), catalog.getPublisherSessionId());
            return;
        }
        Instant expiresAt = parseInstant(catalog.getExpiresAt(), Instant.now().plus(PeerServiceDiscovery.CATALOG_TTL));
        catalogs.put(key, new CatalogSnapshot(
                catalog.getPublisherClientId(),
                catalog.getPublisherClientName() == null ? "" : catalog.getPublisherClientName(),
                catalog.getPublisherSessionId(),
                catalog.getRevision() == null ? 0L : catalog.getRevision(),
                expiresAt,
                services));
        log.info("Peer 服务目录已更新: publisher={} session={} services={}",
                catalog.getPublisherClientName(), catalog.getPublisherSessionId(), services.size());
        for (RemoteServiceView view : remoteServices()) {
            log.info("  {} {} {}", view.publisherClientName(), view.service().getApplication(), view.accessTarget());
        }
    }

    public List<RemoteServiceView> remoteServices() {
        Instant now = Instant.now();
        List<RemoteServiceView> views = new ArrayList<>();
        for (CatalogSnapshot snapshot : catalogs.values()) {
            if (snapshot.expiresAt().isBefore(now)) {
                continue;
            }
            RosterHint hint = rosterLookup.apply(snapshot.publisherClientId());
            for (PeerAdvertisedService service : snapshot.services()) {
                views.add(RemoteServiceView.from(snapshot, hint, service));
            }
        }
        return List.copyOf(views);
    }

    public List<LocalPeerService> localServices() {
        List<LocalPeerService> services = config.getLocalServices();
        return services == null ? List.of() : List.copyOf(services);
    }

    public void setLocalPublished(String serviceId, boolean published) {
        if (!StringUtils.hasText(serviceId)) {
            return;
        }
        if (published) {
            locallyPaused.remove(serviceId.trim());
        } else {
            locallyPaused.add(serviceId.trim());
        }
        probeAndReport();
    }

    public boolean isLocallyPublished(String serviceId) {
        return serviceId == null || !locallyPaused.contains(serviceId);
    }

    public boolean effectiveSharing() {
        PeerServiceSharingStatus sharing = config.getServiceSharing();
        return sharing != null && sharing.isEffectiveEnabled();
    }

    void probeAndReport() {
        synchronized (lock) {
            if (!effectiveSharing() || !hasAuthorizedOnlinePeer.get()) {
                closeBridges();
                return;
            }
            List<PeerAdvertisedService> reachable = new ArrayList<>();
            for (LocalPeerService local : enabledLocals()) {
                if (!PeerServiceDiscovery.probe(local, PROBE_TIMEOUT_MILLIS)) {
                    continue;
                }
                reachable.add(advertised(local));
            }
            List<String> ids = reachable.stream().map(PeerAdvertisedService::getServiceId).toList();
            List<PeerServiceStats> stats = currentStatsLocked();
            List<PeerMdnsCandidate> mdns = mdnsCandidatesLocked();
            List<String> mdnsKeys = mdns.stream()
                    .map(item -> item.getApplication() + ":" + item.getTargetHost() + ":" + item.getTargetPort())
                    .toList();
            if (ids.equals(lastReportedIds) && revision.get() > 0 && statsUnchanged(stats) && mdnsKeys.equals(lastMdnsKeys)) {
                reconcileBridgesLocked();
                return;
            }
            lastReportedIds = ids;
            lastMdnsKeys = mdnsKeys;
            sendReportLocked(true, reachable, stats, mdns);
            reconcileBridgesLocked();
        }
    }

    private void reconcileBridgesLocked() {
        if (!effectiveSharing() || !hasAuthorizedOnlinePeer.get() || !StringUtils.hasText(config.getVirtualIp())) {
            closeBridges();
            return;
        }
        Map<String, LocalPeerService> desired = new LinkedHashMap<>();
        for (LocalPeerService local : enabledLocals()) {
            if (PeerServiceDiscovery.probe(local, PROBE_TIMEOUT_MILLIS)) {
                desired.put(local.getServiceId(), local);
            }
        }
        for (String id : new ArrayList<>(bridges.keySet())) {
            if (!desired.containsKey(id)) {
                PeerServiceForwarder removed = bridges.remove(id);
                closeQuietly(removed);
            }
        }
        for (LocalPeerService local : desired.values()) {
            PeerServiceForwarder current = bridges.get(local.getServiceId());
            if (current != null && current.matches(config.getVirtualIp(), local)) {
                continue;
            }
            closeQuietly(current);
            try {
                bridges.put(local.getServiceId(), bindForwarder(config.getVirtualIp(), local));
                log.info("Peer-only 桥接已监听 {} -> {}:{}",
                        config.getVirtualIp() + ":" + local.getPublishedPort(),
                        local.getTargetHost(), local.getTargetPort());
            } catch (Exception e) {
                log.debug("Peer-only 桥接暂不可用 service={}: {}", local.getServiceId(), e.getMessage());
            }
        }
    }

    private List<LocalPeerService> enabledLocals() {
        List<LocalPeerService> locals = config.getLocalServices();
        if (locals == null || locals.isEmpty()) {
            return List.of();
        }
        List<LocalPeerService> enabled = new ArrayList<>();
        for (LocalPeerService local : locals) {
            if (local != null && local.isEnabled() && !locallyPaused.contains(local.getServiceId())) {
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

    private void sendReportLocked(boolean enabled, List<PeerAdvertisedService> services, List<PeerServiceStats> stats,
                                  List<PeerMdnsCandidate> mdns) {
        PeerControlMessage report = new PeerControlMessage();
        report.setType(PeerControlMessage.TYPE_SERVICE_REPORT);
        report.setEnabled(enabled);
        report.setRevision(revision.incrementAndGet());
        report.setInstanceId(instanceId);
        report.setGeneratedAt(Instant.now().toString());
        report.setExpiresAt(Instant.now().plus(PeerServiceDiscovery.CATALOG_TTL).toString());
        report.setServices(services);
        report.setStats(stats);
        report.setMdnsCandidates(mdns);
        report.setCreatedAtMillis(System.currentTimeMillis());
        lastReportedStats = stats;
        sender.send("", JsonUtil.objectToString(report));
    }

    private void sendWithdrawLocked() {
        lastReportedIds = List.of();
        lastReportedStats = List.of();
        lastMdnsKeys = List.of();
        sendReportLocked(false, List.of(), List.of(), List.of());
    }

    private List<PeerServiceStats> currentStatsLocked() {
        List<PeerServiceStats> stats = new ArrayList<>();
        for (PeerServiceForwarder bridge : bridges.values()) {
            stats.add(bridge.stats());
        }
        return stats;
    }

    private List<PeerMdnsCandidate> mdnsCandidatesLocked() {
        PeerServiceSharingStatus sharing = config.getServiceSharing();
        if (sharing == null || !sharing.isMdnsImportEnabled()) {
            return List.of();
        }
        return PeerMdnsBrowser.browse(Duration.ofMillis(PROBE_TIMEOUT_MILLIS));
    }

    private static PeerServiceForwarder bindForwarder(String virtualIp, LocalPeerService local) throws Exception {
        if (PeerServiceDiscovery.TRANSPORT_UDP.equalsIgnoreCase(local.getTransport())
                || PeerServiceDiscovery.APPLICATION_UDP.equalsIgnoreCase(local.getApplication())) {
            return PeerServiceUdpBridge.bind(virtualIp, local);
        }
        return PeerServiceBridge.bind(virtualIp, local);
    }

    private boolean statsUnchanged(List<PeerServiceStats> stats) {
        if (stats.size() != lastReportedStats.size()) {
            return false;
        }
        for (int i = 0; i < stats.size(); i++) {
            PeerServiceStats left = stats.get(i);
            PeerServiceStats right = lastReportedStats.get(i);
            if (!Objects.equals(left.getServiceId(), right.getServiceId())
                    || left.getBytesIn() != right.getBytesIn()
                    || left.getBytesOut() != right.getBytesOut()
                    || left.getActiveConnections() != right.getActiveConnections()
                    || left.getTotalConnections() != right.getTotalConnections()) {
                return false;
            }
        }
        return true;
    }

    private void closeBridges() {
        for (PeerServiceForwarder bridge : bridges.values()) {
            closeQuietly(bridge);
        }
        bridges.clear();
    }

    private static void closeQuietly(PeerServiceForwarder forwarder) {
        if (forwarder == null) {
            return;
        }
        try {
            forwarder.close();
        } catch (Exception ignored) {
        }
    }

    private static PeerAdvertisedService advertised(LocalPeerService local) {
        PeerAdvertisedService service = new PeerAdvertisedService();
        service.setServiceId(local.getServiceId());
        service.setName(local.getName());
        service.setDescription(local.getDescription());
        service.setTransport(local.getTransport());
        service.setApplication(local.getApplication());
        service.setPublishedPort(local.getPublishedPort());
        service.setPath(local.getPath());
        return service;
    }

    private static Instant parseInstant(String raw, Instant fallback) {
        if (!StringUtils.hasText(raw)) {
            return fallback;
        }
        try {
            return Instant.parse(raw.trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            stopProbeLocked();
            closeBridges();
            catalogs.clear();
        }
        if (ownScheduler) {
            scheduler.shutdownNow();
        }
    }

    public record RosterHint(String virtualIp, boolean online) {
        public static RosterHint unknown() {
            return new RosterHint("", false);
        }
    }

    public record CatalogKey(long publisherClientId, long publisherSessionId) {
    }

    public record CatalogSnapshot(long publisherClientId,
                                  String publisherClientName,
                                  long publisherSessionId,
                                  long revision,
                                  Instant expiresAt,
                                  List<PeerAdvertisedService> services) {
    }

    public record RemoteServiceView(long publisherClientId,
                                    String publisherClientName,
                                    long publisherSessionId,
                                    String virtualIp,
                                    boolean publisherOnline,
                                    boolean fresh,
                                    PeerAdvertisedService service,
                                    String accessTarget,
                                    boolean openable,
                                    boolean copyable,
                                    String unavailableReason) {
        static RemoteServiceView from(CatalogSnapshot snapshot, RosterHint hint, PeerAdvertisedService service) {
            boolean http = PeerServiceDiscovery.APPLICATION_HTTP.equals(service.getApplication())
                    || PeerServiceDiscovery.APPLICATION_HTTPS.equals(service.getApplication());
            boolean fresh = snapshot.expiresAt().isAfter(Instant.now());
            boolean online = hint.online();
            String virtualIp = hint.virtualIp() == null ? "" : hint.virtualIp();
            String reason = !fresh ? "目录已过期"
                    : !online ? "发布端离线"
                    : virtualIp.isBlank() ? "缺少虚拟 IP"
                    : "";
            return new RemoteServiceView(
                    snapshot.publisherClientId(),
                    snapshot.publisherClientName(),
                    snapshot.publisherSessionId(),
                    virtualIp,
                    online,
                    fresh,
                    service,
                    virtualIp.isBlank() ? "" : PeerServiceDiscovery.accessUrl(virtualIp, service),
                    http && reason.isEmpty(),
                    !http && reason.isEmpty(),
                    reason);
        }
    }
}
