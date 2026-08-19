package com.theshuai.specusserver.management.service;

import com.theshuai.common.peermesh.PeerAdvertisedService;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.peermesh.PeerServiceSharingStatus;
import com.theshuai.common.peermesh.PeerServiceStats;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.PeerMeshDevice;
import com.theshuai.specusserver.management.model.PeerMeshServiceSharing;
import com.theshuai.specusserver.management.model.PeerMeshServiceSharingView;
import com.theshuai.specusserver.management.model.PeerMeshSharedService;
import com.theshuai.specusserver.management.model.PeerMeshSharedServiceView;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.repository.PeerMeshServiceSharingRepository;
import com.theshuai.specusserver.management.repository.PeerMeshSharedServiceRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.stream.Collectors;

@Service
@Slf4j
public class PeerServiceDiscoveryService {
    private final PeerMeshService peerMeshService;
    private final PeerMeshServiceSharingRepository sharingRepository;
    private final PeerMeshSharedServiceRepository serviceRepository;
    private final PeerMeshDeviceRepository deviceRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final SpecusMappingRepository specusMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final Map<CatalogKey, CatalogSnapshot> catalogs = new ConcurrentHashMap<>();
    private final Map<CatalogKey, List<com.theshuai.common.peermesh.PeerMdnsCandidate>> mdnsCandidates = new ConcurrentHashMap<>();
    private final Map<Long, ConcurrentLinkedDeque<Long>> reportTimestamps = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<AuditEvent> audits = new ConcurrentLinkedDeque<>();

    public PeerServiceDiscoveryService(PeerMeshService peerMeshService,
                                       PeerMeshServiceSharingRepository sharingRepository,
                                       PeerMeshSharedServiceRepository serviceRepository,
                                       PeerMeshDeviceRepository deviceRepository,
                                       ClientAccountRepository clientAccountRepository,
                                       SpecusMappingRepository specusMappingRepository,
                                       HttpRouteMappingRepository httpRouteMappingRepository) {
        this.peerMeshService = peerMeshService;
        this.sharingRepository = sharingRepository;
        this.serviceRepository = serviceRepository;
        this.deviceRepository = deviceRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.specusMappingRepository = specusMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
    }

    @Transactional(readOnly = true)
    public PeerMeshServiceSharingView sharingStatus(ManagementContext context) {
        String tenantId = context.tenant().tenantId();
        boolean configured = configuredEnabled(tenantId);
        return new PeerMeshServiceSharingView(
                peerMeshService.isEnabled(),
                configured,
                peerMeshService.isEnabled() && configured,
                PeerServiceDiscovery.PROTOCOL_VERSION,
                PeerServiceDiscovery.APPLICATIONS,
                (int) serviceRepository.countByTenantIdAndEnabledTrue(tenantId),
                sharingRepository.findById(tenantId).map(PeerMeshServiceSharing::getUpdatedAt).orElse(null),
                sharingRepository.findById(tenantId).map(PeerMeshServiceSharing::getUpdatedBy).orElse(null),
                sharingRepository.findById(tenantId).map(PeerMeshServiceSharing::isMdnsImportEnabled).orElse(false)
        );
    }

    public PeerServiceSharingStatus sharingFor(ClientAccount account, boolean deviceEnabled) {
        boolean configured = account != null && configuredEnabled(account.getTenantId());
        boolean mdns = account != null && sharingRepository.findById(account.getTenantId())
                .map(PeerMeshServiceSharing::isMdnsImportEnabled).orElse(false);
        return PeerServiceSharingStatus.of(
                peerMeshService.isEnabled(),
                configured,
                deviceEnabled,
                mdns);
    }

    @Transactional
    public SharingMutationResult setSharing(ManagementContext context, Boolean enabled) {
        return setSharing(context, enabled, null);
    }

    public SharingMutationResult setSharing(ManagementContext context, Boolean enabled, Boolean mdnsImportEnabled) {
        requireAdmin(context);
        if (enabled == null && mdnsImportEnabled == null) {
            throw new IllegalArgumentException("enabled or mdnsImportEnabled is required");
        }
        if (Boolean.TRUE.equals(enabled) && !peerMeshService.isEnabled()) {
            throw new IllegalArgumentException("部署端未启用 Peer Mesh，不能开启服务共享");
        }
        String tenantId = context.tenant().tenantId();
        boolean previous = configuredEnabled(tenantId);
        String now = Instant.now().toString();
        PeerMeshServiceSharing row = sharingRepository.findById(tenantId).orElseGet(PeerMeshServiceSharing::new);
        row.setTenantId(tenantId);
        if (enabled != null) {
            row.setEnabled(enabled);
        }
        if (mdnsImportEnabled != null) {
            row.setMdnsImportEnabled(mdnsImportEnabled);
        }
        row.setUpdatedBy(context.username());
        row.setUpdatedAt(now);
        sharingRepository.save(row);
        audit("sharing-toggle", tenantId, null, null, null,
                (enabled != null && enabled ? "enabled" : "updated")
                        + (Boolean.TRUE.equals(row.isMdnsImportEnabled()) ? ",mdns" : ""));
        List<CatalogDelivery> catalogsToPush = List.of();
        if (previous && Boolean.FALSE.equals(enabled)) {
            catalogsToPush = withdrawTenant(tenantId, "sharing-disabled");
        }
        return new SharingMutationResult(sharingStatus(context), true, catalogsToPush);
    }

    @Transactional(readOnly = true)
    public List<PeerMeshSharedServiceView> listServices(ManagementContext context) {
        String tenantId = context.tenant().tenantId();
        List<PeerMeshSharedService> rows = context.isAdmin()
                ? serviceRepository.findByTenantIdOrderByClientNameAscNameAsc(tenantId)
                : serviceRepository.findByTenantIdAndClientIdInOrderByClientNameAscNameAsc(
                        tenantId, visibleClientIds(context));
        return rows.stream().map(row -> toView(row, context.isAdmin())).toList();
    }

    @Transactional
    public PeerMeshSharedServiceView createService(ManagementContext context, ServiceMutation mutation) {
        requireAdmin(context);
        ClientAccount account = requireTenantClient(context, mutation.clientId());
        String serviceId = StringUtils.hasText(mutation.serviceId())
                ? PeerServiceDiscovery.requireServiceId(mutation.serviceId())
                : UUID.randomUUID().toString();
        if (serviceRepository.findByTenantIdAndClientIdAndServiceId(
                context.tenant().tenantId(), account.getId(), serviceId).isPresent()) {
            throw new IllegalArgumentException("serviceId already exists on this client");
        }
        String now = Instant.now().toString();
        PeerMeshSharedService row = new PeerMeshSharedService();
        row.setId(ClientIdGenerator.newId());
        row.setTenantId(context.tenant().tenantId());
        row.setClientId(account.getId());
        row.setClientName(account.getClientName());
        row.setServiceId(serviceId);
        row.setCreatedAt(now);
        applyDefinition(row, mutation, true);
        row.setUpdatedAt(now);
        PeerMeshSharedService saved = serviceRepository.save(row);
        audit("service-create", saved.getTenantId(), saved.getClientId(), null, saved.getServiceId(), "created");
        return toView(saved, true);
    }

    @Transactional
    public ServiceMutationResult updateService(ManagementContext context, long id, ServiceMutation mutation) {
        requireAdmin(context);
        PeerMeshSharedService row = serviceRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .orElseThrow(() -> new IllegalArgumentException("service not found: " + id));
        boolean wasEnabled = row.isEnabled();
        applyDefinition(row, mutation, false);
        row.setUpdatedAt(Instant.now().toString());
        PeerMeshSharedService saved = serviceRepository.save(row);
        audit("service-update", saved.getTenantId(), saved.getClientId(), null, saved.getServiceId(),
                saved.isEnabled() ? "enabled" : "updated");
        List<CatalogDelivery> catalogsToPush = List.of();
        if (wasEnabled && !saved.isEnabled()) {
            catalogsToPush = republishClient(saved.getTenantId(), saved.getClientId(), "service-disabled");
        }
        return new ServiceMutationResult(toView(saved, true), catalogsToPush);
    }

    @Transactional
    public ServiceMutationResult deleteService(ManagementContext context, long id) {
        requireAdmin(context);
        PeerMeshSharedService row = serviceRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .orElseThrow(() -> new IllegalArgumentException("service not found: " + id));
        serviceRepository.delete(row);
        audit("service-delete", row.getTenantId(), row.getClientId(), null, row.getServiceId(), "deleted");
        return new ServiceMutationResult(toView(row, true),
                republishClient(row.getTenantId(), row.getClientId(), "service-deleted"));
    }

    public List<CatalogDelivery> handleReport(ClientAccount source, PeerControlMessage report) {
        return acceptReport(source, report, authenticatedSessionId(source));
    }

    List<CatalogDelivery> acceptReport(ClientAccount source, PeerControlMessage report, long publisherSessionId) {
        if (source == null || report == null) {
            throw new IllegalArgumentException("invalid service-report");
        }
        if (publisherSessionId <= 0) {
            throw new IllegalArgumentException("publisher session is required");
        }
        enforceRateLimit(publisherSessionId);
        long revision = report.getRevision() == null ? 0L : report.getRevision();
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be >= 1");
        }
        CatalogKey key = new CatalogKey(source.getTenantId(), source.getId(), publisherSessionId);
        CatalogSnapshot previous = catalogs.get(key);
        if (previous != null && revision <= previous.revision()) {
            audit("service-report", source.getTenantId(), source.getId(), publisherSessionId, null, "ignored-revision");
            return List.of();
        }
        if (!Boolean.TRUE.equals(report.getEnabled()) || !effectiveSharing(source)) {
            catalogs.remove(key);
            mdnsCandidates.remove(key);
            audit("service-report", source.getTenantId(), source.getId(), publisherSessionId, null, "withdrawn");
            return fanout(source, publisherSessionId, 0L, List.of(), Instant.now().plus(PeerServiceDiscovery.CATALOG_TTL));
        }
        if (!hasAuthorizedOnlinePeer(source)) {
            catalogs.remove(key);
            mdnsCandidates.remove(key);
            audit("service-report", source.getTenantId(), source.getId(), publisherSessionId, null, "no-authorized-peer");
            return List.of();
        }
        List<PeerAdvertisedService> advertised = advertisedFromReport(source, report.getServices());
        Instant generatedAt = parseInstant(report.getGeneratedAt(), Instant.now());
        Instant expiresAt = parseInstant(report.getExpiresAt(), generatedAt.plus(PeerServiceDiscovery.CATALOG_TTL));
        if (!expiresAt.isAfter(generatedAt)) {
            expiresAt = generatedAt.plus(PeerServiceDiscovery.CATALOG_TTL);
        }
        catalogs.put(key, new CatalogSnapshot(
                revision,
                PeerServiceDiscovery.normalizeInstanceId(report.getInstanceId()),
                generatedAt,
                expiresAt,
                advertised,
                source.getClientName(),
                copyStats(report.getStats(), advertised)));
        storeMdns(key, source, report);
        audit("service-report", source.getTenantId(), source.getId(), publisherSessionId, null,
                advertised.isEmpty() ? "empty" : "published");
        return fanout(source, publisherSessionId, revision, advertised, expiresAt);
    }

    public List<CatalogDelivery> onClientDisconnected(ClientAccount account, Long sessionId) {
        if (account == null || sessionId == null) {
            return List.of();
        }
        CatalogKey key = new CatalogKey(account.getTenantId(), account.getId(), sessionId);
        catalogs.remove(key);
        mdnsCandidates.remove(key);
        reportTimestamps.remove(sessionId);
        audit("publisher-offline", account.getTenantId(), account.getId(), sessionId, null, "disconnected");
        return fanout(account, sessionId, 0L, List.of(), Instant.now());
    }

    public List<CatalogDelivery> onAuthorizationChanged(String tenantId) {
        if (!StringUtils.hasText(tenantId)) {
            return List.of();
        }
        List<CatalogDelivery> deliveries = new ArrayList<>();
        for (Map.Entry<CatalogKey, CatalogSnapshot> entry : catalogs.entrySet()) {
            if (!tenantId.equals(entry.getKey().tenantId())) {
                continue;
            }
            ClientAccount publisher = clientAccountRepository.findByIdAndTenantId(
                    entry.getKey().publisherClientId(), tenantId).orElse(null);
            if (publisher == null || !effectiveSharing(publisher)) {
                catalogs.remove(entry.getKey());
                continue;
            }
            deliveries.addAll(fanout(
                    publisher,
                    entry.getKey().publisherSessionId(),
                    entry.getValue().revision(),
                    entry.getValue().services(),
                    entry.getValue().expiresAt()));
        }
        return deliveries;
    }

    public List<CatalogDelivery> withdrawClient(String tenantId, long clientId, String reason) {
        return republishClient(tenantId, clientId, reason);
    }

    public CatalogSnapshot currentCatalog(String tenantId, long clientId, long sessionId) {
        return catalogs.get(new CatalogKey(tenantId, clientId, sessionId));
    }

    public List<CatalogDelivery> expireStale() {
        Instant now = Instant.now();
        List<CatalogDelivery> deliveries = new ArrayList<>();
        catalogs.entrySet().removeIf(entry -> {
            if (entry.getValue().expiresAt().isAfter(now)) {
                return false;
            }
            ClientAccount publisher = clientAccountRepository.findByIdAndTenantId(
                    entry.getKey().publisherClientId(), entry.getKey().tenantId()).orElse(null);
            if (publisher != null) {
                deliveries.addAll(fanout(publisher, entry.getKey().publisherSessionId(), 0L, List.of(), now));
            }
            audit("catalog-expire", entry.getKey().tenantId(), entry.getKey().publisherClientId(),
                    entry.getKey().publisherSessionId(), null, "ttl");
            return true;
        });
        return deliveries;
    }

    private List<CatalogDelivery> republishClient(String tenantId, long clientId, String reason) {
        List<CatalogDelivery> deliveries = new ArrayList<>();
        ClientAccount publisher = clientAccountRepository.findByIdAndTenantId(clientId, tenantId).orElse(null);
        catalogs.entrySet().removeIf(entry -> {
            if (!tenantId.equals(entry.getKey().tenantId()) || entry.getKey().publisherClientId() != clientId) {
                return false;
            }
            if (publisher != null) {
                deliveries.addAll(fanout(publisher, entry.getKey().publisherSessionId(), 0L, List.of(), Instant.now()));
            }
            audit("catalog-withdraw", tenantId, clientId, entry.getKey().publisherSessionId(), null, reason);
            mdnsCandidates.remove(entry.getKey());
            return true;
        });
        return deliveries;
    }

    private List<CatalogDelivery> withdrawTenant(String tenantId, String reason) {
        List<CatalogDelivery> deliveries = new ArrayList<>();
        catalogs.entrySet().removeIf(entry -> {
            if (!tenantId.equals(entry.getKey().tenantId())) {
                return false;
            }
            ClientAccount publisher = clientAccountRepository.findByIdAndTenantId(
                    entry.getKey().publisherClientId(), tenantId).orElse(null);
            if (publisher != null) {
                deliveries.addAll(fanout(publisher, entry.getKey().publisherSessionId(), 0L, List.of(), Instant.now()));
            }
            audit("catalog-withdraw", tenantId, entry.getKey().publisherClientId(),
                    entry.getKey().publisherSessionId(), null, reason);
            mdnsCandidates.remove(entry.getKey());
            return true;
        });
        return deliveries;
    }

    private List<PeerAdvertisedService> advertisedFromReport(ClientAccount source,
                                                             List<PeerAdvertisedService> reported) {
        List<PeerAdvertisedService> sanitized = PeerServiceDiscovery.sanitizeAdvertisedList(reported);
        Map<String, PeerMeshSharedService> definitions = serviceRepository
                .findByTenantIdAndClientIdOrderByNameAsc(source.getTenantId(), source.getId())
                .stream()
                .filter(PeerMeshSharedService::isEnabled)
                .collect(Collectors.toMap(PeerMeshSharedService::getServiceId, item -> item, (left, right) -> left));
        List<PeerAdvertisedService> advertised = new ArrayList<>();
        for (PeerAdvertisedService item : sanitized) {
            PeerMeshSharedService definition = definitions.get(item.getServiceId());
            if (definition == null) {
                continue;
            }
            advertised.add(fromDefinition(definition));
        }
        return List.copyOf(advertised);
    }

    private List<CatalogDelivery> fanout(ClientAccount publisher,
                                         long publisherSessionId,
                                         long revision,
                                         List<PeerAdvertisedService> services,
                                         Instant expiresAt) {
        List<CatalogDelivery> deliveries = new ArrayList<>();
        for (ClientAccount recipient : clientAccountRepository.findByTenantIdOrderByIdDesc(publisher.getTenantId())) {
            if (Objects.equals(recipient.getId(), publisher.getId()) || !peerMeshService.canPeer(publisher, recipient)) {
                continue;
            }
            Channel channel = SessionUtil.getChannel(recipient.getClientName());
            if (channel == null || !SessionUtil.hasLogin(channel)) {
                continue;
            }
            List<PeerAdvertisedService> visible = services.stream()
                    .filter(service -> visibleTo(publisher, recipient, service))
                    .map(PeerServiceDiscovery::copyAdvertised)
                    .toList();
            deliveries.add(new CatalogDelivery(recipient, catalogMessage(
                    publisher, publisherSessionId, revision, visible, expiresAt)));
        }
        return deliveries;
    }

    boolean visibleTo(ClientAccount publisher, ClientAccount recipient, PeerAdvertisedService service) {
        PeerMeshSharedService definition = serviceRepository
                .findByTenantIdAndClientIdAndServiceId(publisher.getTenantId(), publisher.getId(), service.getServiceId())
                .orElse(null);
        if (definition == null || !definition.isEnabled()) {
            return false;
        }
        if (PeerServiceDiscovery.VISIBILITY_OWNER.equals(definition.getVisibility())) {
            return normalizeOwner(publisher.getOwnerUsername()).equals(normalizeOwner(recipient.getOwnerUsername()));
        }
        List<Long> allowed = PeerServiceDiscovery.decodeClientIds(definition.getAllowedClientIds());
        return allowed.isEmpty() || allowed.contains(recipient.getId());
    }

    private PeerControlMessage catalogMessage(ClientAccount publisher,
                                              long publisherSessionId,
                                              long revision,
                                              List<PeerAdvertisedService> services,
                                              Instant expiresAt) {
        PeerControlMessage message = new PeerControlMessage();
        message.setType(PeerControlMessage.TYPE_SERVICE_CATALOG);
        message.setPublisherClientId(publisher.getId());
        message.setPublisherClientName(publisher.getClientName());
        message.setPublisherSessionId(publisherSessionId);
        message.setRevision(revision);
        message.setExpiresAt(expiresAt.toString());
        message.setServices(services);
        message.setCreatedAtMillis(System.currentTimeMillis());
        return message;
    }

    private boolean effectiveSharing(ClientAccount account) {
        if (account == null || !peerMeshService.isEnabled() || !configuredEnabled(account.getTenantId())) {
            return false;
        }
        return deviceRepository.findByTenantIdAndClientId(account.getTenantId(), account.getId())
                .map(PeerMeshDevice::isEnabled)
                .orElse(false);
    }

    private boolean configuredEnabled(String tenantId) {
        return sharingRepository.findById(tenantId).map(PeerMeshServiceSharing::isEnabled).orElse(false);
    }

    private boolean hasAuthorizedOnlinePeer(ClientAccount account) {
        return peerMeshService.allowedRoster(account).stream()
                .anyMatch(PeerMeshService.PeerRosterItem::online);
    }

    private long authenticatedSessionId(ClientAccount source) {
        Channel channel = SessionUtil.getChannel(source.getClientName());
        if (channel == null) {
            throw new IllegalArgumentException("publisher session is required");
        }
        Long sessionId = channel.attr(ServerAttributes.CLIENT_SESSION_ID).get();
        if (sessionId == null || sessionId <= 0) {
            throw new IllegalArgumentException("publisher session is required");
        }
        return sessionId;
    }

    private void enforceRateLimit(long sessionId) {
        long now = System.currentTimeMillis();
        long windowStart = now - PeerServiceDiscovery.REPORT_RATE_WINDOW.toMillis();
        ConcurrentLinkedDeque<Long> stamps = reportTimestamps.computeIfAbsent(sessionId, ignored -> new ConcurrentLinkedDeque<>());
        while (true) {
            Long first = stamps.peekFirst();
            if (first == null || first >= windowStart) {
                break;
            }
            stamps.pollFirst();
        }
        if (stamps.size() >= PeerServiceDiscovery.REPORT_RATE_LIMIT) {
            audit("service-report", null, null, sessionId, null, "rate-limited");
            throw new RateLimitedException("service-report rate limited", 30);
        }
        stamps.addLast(now);
    }

    private void applyDefinition(PeerMeshSharedService row, ServiceMutation mutation, boolean creating) {
        if (mutation == null) {
            throw new IllegalArgumentException("service body is required");
        }
        if (creating || mutation.name() != null) {
            row.setName(PeerServiceDiscovery.requireName(mutation.name()));
        }
        if (creating || mutation.description() != null) {
            row.setDescription(PeerServiceDiscovery.normalizeDescription(mutation.description()));
        }
        if (creating || mutation.application() != null) {
            row.setApplication(PeerServiceDiscovery.requireApplication(mutation.application()));
        }
        row.setTransport(PeerServiceDiscovery.requireTransportForApplication(
                mutation.transport() == null ? row.getTransport() : mutation.transport(),
                row.getApplication()));
        if (creating || mutation.targetHost() != null) {
            row.setTargetHost(PeerServiceDiscovery.requireTargetHost(mutation.targetHost()));
        }
        if (creating || mutation.targetPort() != null) {
            row.setTargetPort(PeerServiceDiscovery.requirePort(mutation.targetPort(), "targetPort"));
        }
        if (creating || mutation.publishedPort() != null) {
            row.setPublishedPort(PeerServiceDiscovery.requirePort(mutation.publishedPort(), "publishedPort"));
        }
        if (creating || mutation.path() != null) {
            row.setPath(PeerServiceDiscovery.normalizePath(mutation.path(), row.getApplication()));
        }
        if (mutation.visibility() != null || creating) {
            row.setVisibility(PeerServiceDiscovery.requireVisibility(mutation.visibility()));
        }
        if (mutation.enabled() != null) {
            row.setEnabled(mutation.enabled());
        } else if (creating) {
            row.setEnabled(false);
        }
        if (mutation.allowedClientIds() != null || creating) {
            row.setAllowedClientIds(PeerServiceDiscovery.encodeClientIds(mutation.allowedClientIds()));
        }
        rejectPublishedPortConflict(row);
    }

    private void rejectPublishedPortConflict(PeerMeshSharedService row) {
        if (!row.isEnabled()) {
            return;
        }
        boolean conflict = serviceRepository
                .findByTenantIdAndClientIdOrderByNameAsc(row.getTenantId(), row.getClientId())
                .stream()
                .anyMatch(existing -> !existing.getId().equals(row.getId())
                        && existing.isEnabled()
                        && existing.getPublishedPort() == row.getPublishedPort());
        if (conflict) {
            throw new IllegalArgumentException("publishedPort already used by another enabled service");
        }
    }

    private PeerMeshSharedServiceView toView(PeerMeshSharedService row, boolean includeTarget) {
        String virtualIp = deviceRepository.findByTenantIdAndClientId(row.getTenantId(), row.getClientId())
                .map(PeerMeshDevice::getVirtualIp)
                .orElse("");
        PeerAdvertisedService advertised = fromDefinition(row);
        List<PeerMeshSharedServiceView.PeerMeshSharedServiceInstanceView> instances = catalogs.entrySet().stream()
                .filter(entry -> entry.getKey().tenantId().equals(row.getTenantId())
                        && entry.getKey().publisherClientId() == row.getClientId())
                .map(entry -> {
                    CatalogSnapshot snapshot = entry.getValue();
                    boolean advertisedNow = snapshot.services().stream()
                            .anyMatch(item -> row.getServiceId().equals(item.getServiceId()));
                    Channel channel = SessionUtil.getChannel(snapshot.publisherClientName());
                    PeerServiceStats stats = statsFor(snapshot.stats(), row.getServiceId());
                    return new PeerMeshSharedServiceView.PeerMeshSharedServiceInstanceView(
                            entry.getKey().publisherSessionId(),
                            snapshot.instanceId(),
                            channel != null && SessionUtil.hasLogin(channel),
                            advertisedNow,
                            snapshot.revision(),
                            snapshot.generatedAt().toString(),
                            snapshot.expiresAt().toString(),
                            advertisedNow ? advertised : null,
                            stats.getBytesIn(),
                            stats.getBytesOut(),
                            stats.getActiveConnections(),
                            stats.getTotalConnections());
                })
                .toList();
        return new PeerMeshSharedServiceView(
                row.getId(),
                row.getServiceId(),
                row.getClientId(),
                row.getClientName(),
                row.getName(),
                row.getDescription(),
                row.getTransport(),
                row.getApplication(),
                includeTarget ? row.getTargetHost() : null,
                includeTarget ? row.getTargetPort() : 0,
                row.getPublishedPort(),
                row.getPath(),
                row.isEnabled(),
                row.getVisibility(),
                PeerServiceDiscovery.decodeClientIds(row.getAllowedClientIds()),
                virtualIp.isBlank() ? null : virtualIp + ":" + row.getPublishedPort(),
                instances,
                row.getCreatedAt(),
                row.getUpdatedAt()
        );
    }

    private PeerAdvertisedService fromDefinition(PeerMeshSharedService row) {
        PeerAdvertisedService service = new PeerAdvertisedService();
        service.setServiceId(row.getServiceId());
        service.setName(row.getName());
        service.setDescription(row.getDescription());
        service.setTransport(row.getTransport());
        service.setApplication(row.getApplication());
        service.setPublishedPort(row.getPublishedPort());
        service.setPath(row.getPath());
        return service;
    }

    private ClientAccount requireTenantClient(ManagementContext context, Long clientId) {
        if (clientId == null || clientId <= 0) {
            throw new IllegalArgumentException("clientId is required");
        }
        return clientAccountRepository.findByIdAndTenantId(clientId, context.tenant().tenantId())
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + clientId));
    }

    private List<Long> visibleClientIds(ManagementContext context) {
        return clientAccountRepository
                .findByTenantIdAndOwnerUsernameOrderByIdDesc(context.tenant().tenantId(), context.username())
                .stream()
                .map(ClientAccount::getId)
                .toList();
    }

    private void requireAdmin(ManagementContext context) {
        if (context == null || !context.isAdmin()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "只有管理员可以修改 Peer 服务共享");
        }
    }

    private void audit(String action, String tenantId, Long clientId, Long sessionId, String serviceId, String reason) {
        log.info("[peer-service-audit] action={} tenant={} client={} session={} serviceId={} reason={}",
                action, tenantId, clientId, sessionId, serviceId, reason);
        audits.addFirst(new AuditEvent(Instant.now().toString(), action, tenantId, clientId, sessionId, serviceId, reason));
        while (audits.size() > 80) {
            audits.pollLast();
        }
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> recentAudits(ManagementContext context) {
        String tenantId = context.tenant().tenantId();
        return audits.stream()
                .filter(event -> tenantId.equals(event.tenantId()))
                .limit(50)
                .toList();
    }

    @Transactional
    public ImportResult importCandidates(ManagementContext context, Long clientId) {
        return importCandidates(context, clientId, "tcp-http");
    }

    @Transactional
    public ImportResult importCandidates(ManagementContext context, Long clientId, String source) {
        requireAdmin(context);
        ClientAccount account = requireTenantClient(context, clientId);
        if ("mdns".equalsIgnoreCase(source)) {
            return importMdns(context, account);
        }
        List<PeerMeshSharedService> existing = serviceRepository
                .findByTenantIdAndClientIdOrderByNameAsc(account.getTenantId(), account.getId());
        Set<String> usedTargets = new LinkedHashSet<>();
        for (PeerMeshSharedService row : existing) {
            usedTargets.add(row.getTargetHost() + ":" + row.getTargetPort());
        }
        List<PeerMeshSharedServiceView> created = new ArrayList<>();
        int skipped = 0;
        if (specusMappingRepository != null) {
            for (SpecusMapping mapping : specusMappingRepository
                    .findByTenantIdAndClientIdOrderByIdDesc(account.getTenantId(), account.getId())) {
                if (importTcp(context, account, mapping.getTargetAddress(), mapping.getTargetPort(),
                        mapping.getListenPort(), "tcp-" + mapping.getListenPort(), "tcp", "", usedTargets, created)) {
                    continue;
                }
                skipped++;
            }
        }
        if (httpRouteMappingRepository != null) {
            for (HttpRouteMapping route : httpRouteMappingRepository
                    .findByTenantIdAndClientIdOrderByIdDesc(account.getTenantId(), account.getId())) {
                ImportCandidate candidate = parseHttpCandidate(route.getTargetBaseUrl(), route.getRoute());
                if (candidate == null
                        || !importTcp(context, account, candidate.host(), candidate.port(), candidate.port(),
                        route.getRoute(), candidate.application(), candidate.path(), usedTargets, created)) {
                    skipped++;
                }
            }
        }
        audit("service-import", account.getTenantId(), account.getId(), null, null,
                "created=" + created.size() + ",skipped=" + skipped);
        return new ImportResult(created.size(), skipped, created);
    }

    private ImportResult importMdns(ManagementContext context, ClientAccount account) {
        if (!sharingFor(account, true).isMdnsImportEnabled()) {
            throw new IllegalArgumentException("mDNS 候选导入未开启");
        }
        List<PeerMeshSharedService> existing = serviceRepository
                .findByTenantIdAndClientIdOrderByNameAsc(account.getTenantId(), account.getId());
        Set<String> usedTargets = new LinkedHashSet<>();
        for (PeerMeshSharedService row : existing) {
            usedTargets.add(row.getTargetHost() + ":" + row.getTargetPort());
        }
        List<PeerMeshSharedServiceView> created = new ArrayList<>();
        int skipped = 0;
        List<com.theshuai.common.peermesh.PeerMdnsCandidate> candidates = new ArrayList<>();
        for (Map.Entry<CatalogKey, List<com.theshuai.common.peermesh.PeerMdnsCandidate>> entry : mdnsCandidates.entrySet()) {
            if (entry.getKey().tenantId().equals(account.getTenantId())
                    && entry.getKey().publisherClientId() == account.getId()) {
                candidates.addAll(entry.getValue());
            }
        }
        for (com.theshuai.common.peermesh.PeerMdnsCandidate candidate : candidates) {
            if (importService(context, account, candidate.getTargetHost(), candidate.getTargetPort(),
                    candidate.getTargetPort(), candidate.getName(), candidate.getTransport(),
                    candidate.getApplication(), "", usedTargets, created)) {
                continue;
            }
            skipped++;
        }
        audit("service-import-mdns", account.getTenantId(), account.getId(), null, null,
                "created=" + created.size() + ",skipped=" + skipped);
        return new ImportResult(created.size(), skipped, created);
    }

    private void storeMdns(CatalogKey key, ClientAccount source, PeerControlMessage report) {
        if (!sharingFor(source, true).isMdnsImportEnabled()) {
            mdnsCandidates.remove(key);
            return;
        }
        List<com.theshuai.common.peermesh.PeerMdnsCandidate> sanitized =
                PeerServiceDiscovery.sanitizeMdnsCandidates(report.getMdnsCandidates());
        if (sanitized.isEmpty()) {
            mdnsCandidates.remove(key);
            return;
        }
        mdnsCandidates.put(key, sanitized);
    }

    private boolean importTcp(ManagementContext context, ClientAccount account, String host, int targetPort,
                              int publishedPort, String name, String application, String path,
                              Set<String> usedTargets, List<PeerMeshSharedServiceView> created) {
        return importService(context, account, host, targetPort, publishedPort, name, "tcp", application, path,
                usedTargets, created);
    }

    private boolean importService(ManagementContext context, ClientAccount account, String host, int targetPort,
                                  int publishedPort, String name, String transport, String application, String path,
                                  Set<String> usedTargets, List<PeerMeshSharedServiceView> created) {
        try {
            String targetHost = PeerServiceDiscovery.requireTargetHost(host);
            String key = targetHost + ":" + targetPort;
            if (!usedTargets.add(key)) {
                return false;
            }
            ServiceMutation mutation = new ServiceMutation(
                    account.getId(), null, name, "imported candidate", transport, application,
                    targetHost, targetPort, publishedPort, path, false, "OWNER", null);
            created.add(createService(context, mutation));
            return true;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static ImportCandidate parseHttpCandidate(String targetBaseUrl, String route) {
        if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
            return null;
        }
        try {
            URI uri = URI.create(targetBaseUrl.trim());
            String scheme = uri.getScheme() == null ? "http" : uri.getScheme().toLowerCase();
            String application = "https".equals(scheme) ? "https" : "http";
            String host = uri.getHost();
            int port = uri.getPort() > 0 ? uri.getPort() : ("https".equals(application) ? 443 : 80);
            String path = uri.getPath() == null || uri.getPath().isBlank() ? "/" : uri.getPath();
            if (host == null) {
                return null;
            }
            return new ImportCandidate(host, port, application, path, route);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static List<PeerServiceStats> copyStats(List<PeerServiceStats> raw, List<PeerAdvertisedService> advertised) {
        if (raw == null || raw.isEmpty() || advertised == null) {
            return List.of();
        }
        Set<String> ids = advertised.stream().map(PeerAdvertisedService::getServiceId).collect(Collectors.toSet());
        List<PeerServiceStats> copy = new ArrayList<>();
        for (PeerServiceStats item : raw) {
            if (item == null || item.getServiceId() == null || !ids.contains(item.getServiceId())) {
                continue;
            }
            PeerServiceStats stats = new PeerServiceStats();
            stats.setServiceId(item.getServiceId());
            stats.setBytesIn(Math.max(0, item.getBytesIn()));
            stats.setBytesOut(Math.max(0, item.getBytesOut()));
            stats.setActiveConnections(Math.max(0, item.getActiveConnections()));
            stats.setTotalConnections(Math.max(0, item.getTotalConnections()));
            copy.add(stats);
        }
        return List.copyOf(copy);
    }

    private static PeerServiceStats statsFor(List<PeerServiceStats> stats, String serviceId) {
        if (stats != null) {
            for (PeerServiceStats item : stats) {
                if (item != null && serviceId.equals(item.getServiceId())) {
                    return item;
                }
            }
        }
        return new PeerServiceStats();
    }

    private Instant parseInstant(String raw, Instant fallback) {
        if (!StringUtils.hasText(raw)) {
            return fallback;
        }
        try {
            return Instant.parse(raw.trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    private String normalizeOwner(String owner) {
        return owner == null ? "" : owner.trim();
    }

    public record ServiceMutation(
            Long clientId,
            String serviceId,
            String name,
            String description,
            String transport,
            String application,
            String targetHost,
            Integer targetPort,
            Integer publishedPort,
            String path,
            Boolean enabled,
            String visibility,
            java.util.List<Long> allowedClientIds
    ) {
    }

    public record SharingMutationResult(PeerMeshServiceSharingView status, boolean pushConfig,
                                        List<CatalogDelivery> catalogs) {
    }

    public record ServiceMutationResult(PeerMeshSharedServiceView service, List<CatalogDelivery> catalogs) {
    }

    public record CatalogDelivery(ClientAccount recipient, PeerControlMessage catalog) {
    }

    public record CatalogKey(String tenantId, long publisherClientId, long publisherSessionId) {
    }

    public record CatalogSnapshot(long revision,
                                  String instanceId,
                                  Instant generatedAt,
                                  Instant expiresAt,
                                  List<PeerAdvertisedService> services,
                                  String publisherClientName,
                                  List<PeerServiceStats> stats) {
    }

    public record AuditEvent(String at, String action, String tenantId, Long clientId, Long sessionId,
                             String serviceId, String reason) {
    }

    public record ImportResult(int created, int skipped, List<PeerMeshSharedServiceView> services) {
    }

    private record ImportCandidate(String host, int port, String application, String path, String route) {
    }
}
