package com.theshuai.specusserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerDataFrameHeader;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.peermesh.PeerServiceSharingStatus;
import com.theshuai.common.peermesh.PeerUdpProbe;
import com.theshuai.common.security.HmacSigner;
import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.PeerMeshAcl;
import com.theshuai.specusserver.management.model.PeerMeshAclView;
import com.theshuai.specusserver.management.model.PeerMeshDevice;
import com.theshuai.specusserver.management.model.PeerMeshDeviceView;
import com.theshuai.specusserver.management.model.PeerMeshPathStatsView;
import com.theshuai.specusserver.management.model.PeerMeshServiceSharing;
import com.theshuai.specusserver.management.model.PeerMeshSession;
import com.theshuai.specusserver.management.model.PeerMeshSessionView;
import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.PeerMeshAclRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.common.peermesh.LocalPeerService;
import com.theshuai.specusserver.management.model.PeerMeshSharedService;
import com.theshuai.specusserver.management.repository.PeerMeshServiceSharingRepository;
import com.theshuai.specusserver.management.repository.PeerMeshSessionRepository;
import com.theshuai.specusserver.management.repository.PeerReadSnapshotRepository;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementWriteAuthority;
import com.theshuai.specusserver.peer.TurnCredentialService;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.session.SessionUtil;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

@Service
@Slf4j
public class PeerMeshService {
    public static final String PATH_DIRECT = "DIRECT";
    public static final String PATH_RELAY = "RELAY";
    public static final String STATUS_NEGOTIATING = "NEGOTIATING";
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_CLOSED = "CLOSED";
    private static final long RELAY_AUTH_CACHE_TTL_NANOS = TimeUnit.SECONDS.toNanos(30);

    private final PeerMeshProperties properties;
    private final PeerMeshDeviceRepository deviceRepository;
    private final PeerMeshAclRepository aclRepository;
    private final PeerMeshSessionRepository sessionRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final TurnCredentialService turnCredentialService;
    private final PeerMeshServiceSharingRepository sharingRepository;
    private final ManagementWriteAuthority authority;
    private final PeerReadSnapshotRepository peerReads;
    private final Map<Long, RelayAuthorization> relayAuthorizationCache = new ConcurrentHashMap<>();
    private final Map<Long, AtomicLong> pendingRelayBytes = new ConcurrentHashMap<>();
    private final Map<Long, String> sessionTokenCache = new ConcurrentHashMap<>();
    // Guard publication and invalidation together. A detached in-flight publication keeps its
    // old fence: closing/invalidation removes that fence, so a later callback cannot resurrect it.
    private final Object sessionCacheMonitor = new Object();
    private final Map<Long, SessionCacheFence> sessionCacheFences = new LinkedHashMap<>();
    private final TransactionTemplate transactionTemplate;
    private final Counter relayTrafficFlushFailures;
    private final AtomicLong lastRelayTrafficFlushSuccessMillis = new AtomicLong();
    private volatile long lastExpireMillis;

    public PeerMeshService(PeerMeshProperties properties,
                           PeerMeshDeviceRepository deviceRepository,
                           PeerMeshAclRepository aclRepository,
                           PeerMeshSessionRepository sessionRepository,
                           ClientAccountRepository clientAccountRepository,
                           TurnCredentialService turnCredentialService,
                           PeerMeshServiceSharingRepository sharingRepository,
                           PlatformTransactionManager transactionManager,
                           MeterRegistry meterRegistry,
                           ManagementWriteAuthority authority,
                           PeerReadSnapshotRepository peerReads) {
        this.properties = properties;
        this.deviceRepository = deviceRepository;
        this.aclRepository = aclRepository;
        this.sessionRepository = sessionRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.turnCredentialService = turnCredentialService;
        this.sharingRepository = sharingRepository;
        this.authority = authority;
        this.peerReads = peerReads;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.relayTrafficFlushFailures = Counter.builder("specus.peer_mesh.relay.traffic.flush.failures")
                .description("Relay traffic batches restored after a persistence failure")
                .register(meterRegistry);
        Gauge.builder("specus.peer_mesh.relay.traffic.pending.bytes", this, PeerMeshService::pendingRelayByteCount)
                .description("Relay traffic bytes waiting to be persisted")
                .register(meterRegistry);
        Gauge.builder("specus.peer_mesh.relay.traffic.flush.lag.seconds", lastRelayTrafficFlushSuccessMillis,
                        lastSuccess -> lastSuccess.get() <= 0
                                ? 0
                                : Math.max(0, System.currentTimeMillis() - lastSuccess.get()) / 1000.0)
                .description("Seconds since the last successful relay traffic flush")
                .register(meterRegistry);
    }

    public boolean isEnabled() {
        return properties.isEnabled();
    }

    private List<LocalPeerService> localServices(PeerReadSnapshotRepository.Snapshot snapshot, int clientProtocolVersion) {
        if (clientProtocolVersion < 2) {
            return List.of();
        }
        if (snapshot.source() == null || !snapshot.source().available(snapshot.tenant())) return List.of();
        return snapshot.definitions().stream()
                .sorted(java.util.Comparator.comparing(PeerMeshSharedService::getName).thenComparing(PeerMeshSharedService::getId))
                .map(row -> toLocalService(snapshot, row))
                .toList();
    }

    private LocalPeerService toLocalService(PeerReadSnapshotRepository.Snapshot publisher, PeerMeshSharedService row) {
        LocalPeerService service = new LocalPeerService();
        service.setServiceId(row.getServiceId());
        service.setName(row.getName());
        service.setDescription(row.getDescription());
        service.setTransport(row.getTransport());
        service.setApplication(row.getApplication());
        service.setTargetHost(row.getTargetHost());
        service.setTargetPort(row.getTargetPort());
        service.setPublishedPort(row.getPublishedPort());
        service.setPath(row.getPath());
        service.setEnabled(row.isEnabled());
        service.setVisibility(row.getVisibility());
        service.setAllowedPeerVirtualIps(allowedPeerVirtualIps(publisher, row));
        return service;
    }

    private List<String> allowedPeerVirtualIps(PeerReadSnapshotRepository.Snapshot publisher, PeerMeshSharedService definition) {
        if (publisher.source() == null || definition == null || !definition.isEnabled()) {
            return List.of();
        }
        List<Long> explicit = PeerServiceDiscovery.decodeClientIds(definition.getAllowedClientIds());
        // The consumer initiates toward this publisher, not the reverse direction.
        return publisher.edges().stream()
                .filter(edge -> edge.target().id() != publisher.source().id())
                .filter(edge -> edge.incoming(publisher.tenant()))
                .map(PeerReadSnapshotRepository.Edge::target)
                .filter(recipient -> PeerServiceDiscovery.VISIBILITY_OWNER.equals(definition.getVisibility())
                        ? normalizeOwner(publisher.source().owner()).equals(normalizeOwner(recipient.owner()))
                        : explicit.isEmpty() || explicit.contains(recipient.id()))
                .map(PeerReadSnapshotRepository.Peer::virtualIp)
                .filter(StringUtils::hasText)
                .sorted()
                .distinct()
                .toList();
    }

    @Transactional
    public ClientAuthLoginResponse.PeerMeshConfig buildLoginConfig(ClientAccount account,
                                                                  ClientEnvironmentInfo environment,
                                                                  String requestServerName) {
        account = lockRuntimeClient(account);
        PeerMeshDevice device = null;
        if (properties.isEnabled()) {
            device = ensureDevice(account, environment);
        }
        int clientProtocolVersion = environment == null || environment.getClientPeerServiceCapabilities() == null
                ? 0
                : PeerServiceDiscovery.normalizeVersion(environment.getClientPeerServiceCapabilities().getVersion());
        return buildConfig(account, device, requestServerName, clientProtocolVersion, readPeers(account));
    }

    @Transactional
    public ClientAuthLoginResponse.PeerMeshConfig buildRuntimeConfig(ClientAccount account) {
        account = lockRuntimeClient(account);
        PeerMeshDevice device = null;
        if (properties.isEnabled()) {
            device = currentDevice(account);
        }
        var snapshot = readPeers(account);
        return buildConfig(account, device, null, currentPeerServiceProtocolVersion(snapshot), snapshot);
    }

    private ClientAuthLoginResponse.PeerMeshConfig buildConfig(ClientAccount account,
                                                               PeerMeshDevice device,
                                                               String requestServerName,
                                                               int clientProtocolVersion,
                                                               PeerReadSnapshotRepository.Snapshot snapshot) {
        ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
        config.setEnabled(false);
        config.setClientId(account.getId());
        config.setClientName(account.getClientName());
        config.setCidr(properties.getCidr());
        config.setSessionTtlSeconds(properties.getSessionTtlSeconds());
        config.setPublicStunServers(publicStunServers());
        boolean configuredSharing = sharingRepository.findById(account.getTenantId())
                .map(PeerMeshServiceSharing::isEnabled)
                .orElse(false);
        boolean mdnsImport = sharingRepository.findById(account.getTenantId())
                .map(PeerMeshServiceSharing::isMdnsImportEnabled)
                .orElse(false);
        boolean deviceEnabled = properties.isEnabled() && device != null && device.isEnabled();
        config.setPeerServiceDiscoveryVersion(PeerServiceDiscovery.PROTOCOL_VERSION);
        config.setServiceSharing(PeerServiceSharingStatus.of(
                properties.isEnabled(), configuredSharing, deviceEnabled, mdnsImport));
        config.setLocalServices(localServices(snapshot, clientProtocolVersion));
        if (!properties.isEnabled() || device == null) {
            return config;
        }
        config.setEnabled(device.isEnabled());
        config.setVirtualIp(device.getVirtualIp());
        config.setStunHost(resolveStunHost(requestServerName));
        config.setTurnHost(resolvePeerHost(requestServerName));
        config.setStunPort(resolveStunPort());
        config.setTurnPort(properties.getStunTurnPort());
        TurnCredentialService.TurnCredential turnCredential =
                turnCredentialService.issue("pm-" + account.getId());
        config.setIceUsername(turnCredential.username());
        config.setIceCredential(turnCredential.credential());
        config.setIceRealm(turnCredential.realm());
        config.setIceNonce(turnCredential.nonce());
        config.setServerPublicKey(serverPublicKey());
        config.setClientPublicKey(device.getPublicKey());
        return config;
    }

    private int currentPeerServiceProtocolVersion(PeerReadSnapshotRepository.Snapshot snapshot) {
        var capabilities = boundCapabilities(snapshot, snapshot.source());
        return capabilities == null ? 0 : capabilities.discoveryVersion();
    }

    @Transactional
    public PeerMeshDevice ensureDevice(ClientAccount account, ClientEnvironmentInfo environment) {
        account = lockRuntimeClient(account);
        PeerMeshDevice device = currentDevice(account);
        device.setClientName(account.getClientName());
        device.setOwnerUsername(normalizeOwner(account.getOwnerUsername()));
        if (environment != null && StringUtils.hasText(environment.getPeerPublicKey())) {
            device.setPublicKey(limit(environment.getPeerPublicKey().trim(), 256));
        }
        device.setLastSeenAt(Instant.now().toString());
        device.setUpdatedAt(Instant.now().toString());
        return deviceRepository.save(device);
    }

    @Transactional(readOnly = true)
    public List<PeerMeshDeviceView> listDevices(ManagementContext context) {
        List<PeerMeshDevice> devices = context.isAdmin()
                ? deviceRepository.findByTenantIdOrderByClientNameAsc(context.tenant().tenantId())
                : deviceRepository.findByTenantIdAndOwnerUsernameOrderByClientNameAsc(
                context.tenant().tenantId(), context.username());
        return devices.stream().map(this::toDeviceView).toList();
    }

    @Transactional
    public PeerMeshDeviceView updateDevice(ManagementContext context, long clientId, DeviceMutation mutation) {
        ManagementContext currentActor = authority.current(context);
        ClientAccount current = clientAccountRepository.lockCurrent(clientId, currentActor.tenant().tenantId())
                .filter(account -> currentActor.isAdmin() || currentActor.username().equals(account.getOwnerUsername()))
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + clientId));
        PeerMeshDevice device = deviceRepository.lockCurrent(currentActor.tenant().tenantId(), clientId)
                .orElseThrow(() -> new IllegalArgumentException("peer device not found: " + clientId));
        device.setOwnerUsername(normalizeOwner(current.getOwnerUsername()));
        device.setClientName(current.getClientName());
        if (mutation.enabled() != null) {
            device.setEnabled(mutation.enabled());
        }
        device.setUpdatedAt(Instant.now().toString());
        return toDeviceView(deviceRepository.save(device));
    }

    @Transactional(readOnly = true)
    public List<PeerMeshAclView> listAcls(ManagementContext context) {
        List<PeerMeshAcl> acls = context.isAdmin()
                ? aclRepository.findByTenantIdOrderByIdDesc(context.tenant().tenantId())
                : aclRepository.findByTenantIdAndOwnerUsernameOrderByIdDesc(context.tenant().tenantId(), context.username());
        return acls.stream().map(this::toAclView).toList();
    }

    @Transactional
    public PeerMeshAclView createAcl(ManagementContext context, AclMutation mutation) {
        context = authority.current(context);
        long sourceId = requireId(mutation.sourceClientId(), "sourceClientId"), targetId = requireId(mutation.targetClientId(), "targetClientId");
        Map<Long, ClientAccount> current = clientAccountRepository.lockCurrentAll(List.of(sourceId, targetId), context.tenant().tenantId());
        ClientAccount source = current.get(sourceId), target = current.get(targetId);
        if (source == null || target == null || !context.isAdmin() && !context.username().equals(normalizeOwner(source.getOwnerUsername())))
            throw new IllegalArgumentException("client not found");
        if (source.getId().equals(target.getId())) {
            throw new IllegalArgumentException("source and target cannot be the same client");
        }
        if (!context.isAdmin() && !normalizeOwner(target.getOwnerUsername()).equals(context.username())) {
            throw new IllegalArgumentException("普通用户不能创建跨用户 peer ACL");
        }
        PeerMeshAcl acl = new PeerMeshAcl();
        acl.setId(ClientIdGenerator.newId());
        acl.setTenantId(context.tenant().tenantId());
        acl.setCreatedAt(Instant.now().toString());
        acl.setOwnerUsername(context.username());
        acl.setSourceClientId(source.getId());
        acl.setSourceClientName(source.getClientName());
        acl.setTargetClientId(target.getId());
        acl.setTargetClientName(target.getClientName());
        acl.setAllowed(mutation.allowed() == null || mutation.allowed());
        if (mutation.direction() != null) {
            String dir = mutation.direction().toUpperCase(java.util.Locale.ROOT);
            if (!"OUTBOUND".equals(dir) && !"INBOUND".equals(dir) && !"BOTH".equals(dir)) {
                throw new IllegalArgumentException("invalid direction: " + mutation.direction());
            }
            acl.setDirection(dir);
        }
        acl.setUpdatedAt(Instant.now().toString());
        return toAclView(aclRepository.upsertCurrent(acl, mutation.direction() != null));
    }

    @Transactional
    public void deleteAcl(ManagementContext context, long id) {
        ManagementContext actor = authority.current(context);
        PeerMeshAcl hint = aclRepository.findById(id).filter(row -> row.getTenantId().equals(actor.tenant().tenantId()))
                .orElseThrow(() -> new IllegalArgumentException("peer ACL not found: " + id));
        clientAccountRepository.lockCurrentAll(List.of(hint.getSourceClientId(), hint.getTargetClientId()), actor.tenant().tenantId());
        PeerMeshAcl acl = aclRepository.lockCurrent(id, actor.tenant().tenantId())
                .filter(row -> Objects.equals(row.getSourceClientId(), hint.getSourceClientId()) && Objects.equals(row.getTargetClientId(), hint.getTargetClientId()))
                .filter(row -> actor.isAdmin() || row.getOwnerUsername().equals(actor.username()))
                .orElseThrow(() -> new IllegalArgumentException("peer ACL not found: " + id));
        aclRepository.deleteCurrent(acl.getId(), actor.tenant().tenantId());
    }

    @Transactional(readOnly = true)
    public boolean canPeer(ClientAccount source, ClientAccount target) {
        if (source == null || source.getId() == null || source.getTenantId() == null || target == null || target.getId() == null
                || !Objects.equals(source.getTenantId(), target.getTenantId())) return false;
        var snapshot = peerReads.readPair(source.getTenantId(), source.getId(), target.getId());
        return snapshot.edge(target.getId()).map(edge -> edge.outgoing(snapshot.tenant())).orElse(false);
    }

    @Transactional(readOnly = true)
    public PeerIdentity peerIdentity(ClientAccount account) {
        if (account == null) {
            return new PeerIdentity("", "");
        }
        var snapshot = account.getId() == null || account.getTenantId() == null
                ? PeerReadSnapshotRepository.Snapshot.empty(null)
                : peerReads.readPair(account.getTenantId(), account.getId(), account.getId());
        var peer = snapshot.source();
        return peer != null && peer.available(snapshot.tenant())
                ? new PeerIdentity(peer.virtualIp(), peer.publicKey()) : new PeerIdentity("", "");
    }

    @Transactional
    public PeerSessionGrant createSession(ClientAccount source, ClientAccount target, String pathType) {
        if (source == null || target == null || source.getTenantId() == null || !source.getTenantId().equals(target.getTenantId()))
            throw new IllegalArgumentException("peer access denied");
        Map<Long, ClientAccount> current = clientAccountRepository.lockCurrentAll(List.of(source.getId(), target.getId()), source.getTenantId());
        source = current.get(source.getId()); target = current.get(target.getId());
        if (!canPeerLocked(source, target)) {
            throw new IllegalArgumentException("peer access denied");
        }
        Instant now = Instant.now();
        Optional<PeerSessionGrant> reusable = reusableSessionGrant(source, target, now);
        if (reusable.isPresent()) {
            return reusable.get();
        }
        String token = shortToken(source.getClientName(), target.getClientName(), String.valueOf(now.toEpochMilli()));
        PeerMeshSession session = new PeerMeshSession();
        session.setId(ClientIdGenerator.newId());
        session.setTenantId(source.getTenantId());
        session.setSourceClientId(source.getId());
        session.setSourceClientName(source.getClientName());
        session.setTargetClientId(target.getId());
        session.setTargetClientName(target.getClientName());
        session.setPathType(StringUtils.hasText(pathType) ? pathType : PATH_DIRECT);
        session.setStatus(STATUS_NEGOTIATING);
        session.setTokenHash(HexFormat.of().formatHex(HmacSigner.sha256(token)));
        session.setStartedAt(now.toString());
        session.setUpdatedAt(now.toString());
        session.setExpiresAt(SortableInstant.format(now.plusSeconds(properties.getSessionTtlSeconds())));
        PeerMeshSession saved = sessionRepository.save(session);
        new SessionCachePublication(saved.getId(), token).submit(() -> sessionTokenCache.put(saved.getId(), token));
        return new PeerSessionGrant(toSessionView(saved), token);
    }

    private boolean canPeerLocked(ClientAccount source, ClientAccount target) {
        if (source == null || target == null || !source.isEnabled() || !target.isEnabled()) return false;
        if (!deviceRepository.lockCurrent(source.getTenantId(), source.getId()).map(PeerMeshDevice::isEnabled).orElse(false)
                || !deviceRepository.lockCurrent(target.getTenantId(), target.getId()).map(PeerMeshDevice::isEnabled).orElse(false)) return false;
        if (normalizeOwner(source.getOwnerUsername()).equals(normalizeOwner(target.getOwnerUsername()))) return true;
        return aclRepository.lockPair(source.getTenantId(), source.getId(), target.getId()).filter(PeerMeshAcl::isAllowed)
                .filter(acl -> "OUTBOUND".equals(acl.getDirection()) || "BOTH".equals(acl.getDirection())).isPresent()
                || aclRepository.lockPair(source.getTenantId(), target.getId(), source.getId()).filter(PeerMeshAcl::isAllowed)
                .filter(acl -> "INBOUND".equals(acl.getDirection()) || "BOTH".equals(acl.getDirection())).isPresent();
    }

    private Optional<PeerSessionGrant> reusableSessionGrant(ClientAccount source, ClientAccount target, Instant now) {
        List<PeerMeshSession> sessions = sessionRepository.findOpenBetweenClients(
                source.getTenantId(),
                source.getId(),
                target.getId(),
                STATUS_CLOSED);
        for (PeerMeshSession session : lockSessionRows(sessions)) {
            ClientAccount originalSource = Objects.equals(session.getSourceClientId(), source.getId()) ? source : target;
            ClientAccount originalTarget = Objects.equals(session.getTargetClientId(), target.getId()) ? target : source;
            if (!canPeerLocked(originalSource, originalTarget)) {
                markClosed(session, now); sessionRepository.saveCurrent(session); continue;
            }
            if (closeIfExpired(session, now)) {
                sessionRepository.saveCurrent(session);
                continue;
            }
            String token = pendingOrCachedSessionToken(session.getId());
            if (!StringUtils.hasText(token)) {
                continue;
            }
            return Optional.of(new PeerSessionGrant(toSessionView(session), token));
        }
        return Optional.empty();
    }

    public record SignalPeer(ClientAccount account, PeerIdentity identity) {}
    public record AuthorizedSignal(SignalPeer source, SignalPeer target, PeerSessionGrant grant) {}

    /** Current directional access without throwing for an expected denial. Catalog withdrawals
     * must still commit; catching an exception from another transactional service would instead
     * leave their transaction rollback-only. Ordered parent/policy locks survive the caller TX. */
    @Transactional
    public boolean canPeerCurrent(ClientAccount source, ClientAccount target) {
        if (source == null || target == null || source.getId() == null || target.getId() == null
                || source.getTenantId() == null || !source.getTenantId().equals(target.getTenantId())) return false;
        var current=clientAccountRepository.lockCurrentAll(List.of(source.getId(),target.getId()),source.getTenantId());
        return canPeerLocked(current.get(source.getId()),current.get(target.getId()));
    }

    /** Control forwarding must use current authority, not readonly/JPA roster hints. This also
     * runs again on the publication worker, before any network write and after the producer commits. */
    @Transactional
    public AuthorizedSignal authorizeSignal(ClientAccount source, ClientAccount target, Long sessionId, String suppliedToken) {
        if (source == null || target == null || source.getId() == null || target.getId() == null
                || source.getTenantId() == null || !source.getTenantId().equals(target.getTenantId()))
            throw new IllegalArgumentException("peer access denied");
        var parents = clientAccountRepository.lockCurrentAll(List.of(source.getId(), target.getId()), source.getTenantId());
        ClientAccount a = parents.get(source.getId()), b = parents.get(target.getId());
        if (!canPeerLocked(a,b)) throw new IllegalArgumentException("peer access denied");
        PeerSessionGrant grant = null;
        if (sessionId != null) {
            PeerMeshSession row = sessionRepository.lockCurrent(sessionId)
                    .filter(current -> a.getTenantId().equals(current.getTenantId()))
                    .filter(current -> Objects.equals(current.getSourceClientId(),a.getId()) && Objects.equals(current.getTargetClientId(),b.getId())
                            || Objects.equals(current.getSourceClientId(),b.getId()) && Objects.equals(current.getTargetClientId(),a.getId()))
                    .filter(current -> !STATUS_CLOSED.equals(current.getStatus()) && !isExpired(current,Instant.now()))
                    .orElseThrow(() -> new IllegalArgumentException("peer session unavailable"));
            if (!canPeerLocked(parents.get(row.getSourceClientId()),parents.get(row.getTargetClientId())))
                throw new IllegalArgumentException("peer session unavailable");
            String token = pendingOrCachedSessionToken(sessionId);
            if (!matchesSessionToken(row,token)) token = suppliedToken;
            if (!matchesSessionToken(row,token)) throw new IllegalArgumentException("peer session token unavailable");
            grant = new PeerSessionGrant(toSessionView(row),token);
        }
        var ad = deviceRepository.lockCurrent(a.getTenantId(),a.getId()).orElseThrow();
        var bd = deviceRepository.lockCurrent(b.getTenantId(),b.getId()).orElseThrow();
        return new AuthorizedSignal(new SignalPeer(a,new PeerIdentity(ad.getVirtualIp(),ad.getPublicKey())),
                new SignalPeer(b,new PeerIdentity(bd.getVirtualIp(),bd.getPublicKey())),grant);
    }

    @Transactional
    public void publishAuthorizedSignal(ClientAccount source, ClientAccount target, Long sessionId, String token,
                                        java.util.function.Consumer<AuthorizedSignal> publisher) {
        // This transaction changes no session/grant state. Holding current parents/policy here
        // linearizes forwarding with concurrent ownership/ACL writers; the grant already committed.
        publisher.accept(authorizeSignal(source,target,sessionId,token));
    }

    private boolean matchesSessionToken(PeerMeshSession row, String token) {
        return StringUtils.hasText(token) && StringUtils.hasText(row.getTokenHash()) && MessageDigest.isEqual(
                row.getTokenHash().getBytes(StandardCharsets.US_ASCII),
                HexFormat.of().formatHex(HmacSigner.sha256(token)).getBytes(StandardCharsets.US_ASCII));
    }

    public record SignalClosure(PeerMeshSessionView session, ClientAccount source, ClientAccount target) {}
    @Transactional
    public SignalClosure closeSignalSession(ClientAccount reporter, PeerControlMessage close) {
        if (close.getSessionId() == null || close.getSessionId() <= 0) throw new IllegalArgumentException("sessionId is required");
        CurrentPeerSession current = findReportableSession(reporter,close.getSessionId());
        markClosed(current.row(),Instant.now());
        var view = toSessionView(sessionRepository.saveCurrent(current.row()));
        return new SignalClosure(view,current.parents().get(current.row().getSourceClientId()),current.parents().get(current.row().getTargetClientId()));
    }

    @Transactional
    public PeerMeshSessionView reportPath(ClientAccount reporter, PeerControlMessage report) {
        if (report.getSessionId() == null || report.getSessionId() <= 0) {
            throw new IllegalArgumentException("sessionId is required");
        }
        CurrentPeerSession current = findReportableSession(reporter, report.getSessionId());
        PeerMeshSession session = current.row();
        Instant now = Instant.now();
        if (!current.allowed() || closeIfExpired(session, now)) {
            if (!current.allowed()) markClosed(session, now);
            return toSessionView(sessionRepository.saveCurrent(session));
        }
        if (StringUtils.hasText(report.getPathType())) {
            if (session.getDirectBytes() <= 0 && session.getRelayBytes() <= 0) {
                session.setPathType(limit(report.getPathType(), 40));
            } else {
                session.setPathType(effectivePathType(session));
            }
        }
        session.setStatus(StringUtils.hasText(report.getStatus())
                ? limit(report.getStatus(), 40)
                : STATUS_ACTIVE);
        if (STATUS_CLOSED.equals(session.getStatus())) markClosed(session, now);
        session.setRttMillis(report.getRttMillis());
        session.setLocalEndpoint(limit(report.getLocalEndpoint(), 255));
        session.setRemoteEndpoint(limit(report.getRemoteEndpoint(), 255));
        session.setUpdatedAt(now.toString());
        session.setLastKeepaliveAt(now.toString());
        invalidateRelayAuthorization(session.getId());
        return toSessionView(sessionRepository.saveCurrent(session));
    }

    @Transactional
    public PeerMeshSessionView reportTraffic(ClientAccount reporter, PeerControlMessage report) {
        if (report.getSessionId() == null || report.getSessionId() <= 0) {
            throw new IllegalArgumentException("sessionId is required");
        }
        CurrentPeerSession current = findReportableSession(reporter, report.getSessionId());
        PeerMeshSession session = current.row();
        Instant now = Instant.now();
        if (!current.allowed()) markClosed(session, now);
        else if (!closeIfExpired(session, now)) {
            applyTraffic(session, Math.max(0, report.getDirectBytes()), Math.max(0, report.getRelayBytes()), now);
        }
        return toSessionView(sessionRepository.saveCurrent(session));
    }

    @Transactional
    public PeerMeshDeviceView reportDevice(ClientAccount reporter, PeerControlMessage report) {
        reporter = lockRuntimeClient(reporter);
        PeerMeshDevice device = currentDevice(reporter);
        Instant now = Instant.now();
        device.setClientName(reporter.getClientName());
        device.setOwnerUsername(normalizeOwner(reporter.getOwnerUsername()));
        if (hasVirtualDeviceReport(report)) {
            if (report.getVirtualDeviceMode() != null) {
                device.setVirtualDeviceMode(limit(report.getVirtualDeviceMode(), 80));
            }
            if (report.getVirtualDeviceName() != null) {
                device.setVirtualDeviceName(limit(report.getVirtualDeviceName(), 80));
            }
            if (report.getVirtualDeviceStatus() != null) {
                device.setVirtualDeviceStatus(limit(report.getVirtualDeviceStatus(), 80));
            }
            if (report.getVirtualDeviceError() != null) {
                device.setVirtualDeviceError(limit(report.getVirtualDeviceError(), 512));
            }
            device.setVirtualDeviceUpdatedAt(now.toString());
        }
        if (report.getNatType() != null) {
            device.setNatType(limit(report.getNatType(), 80));
        }
        if (report.getNatMappingBehavior() != null) {
            device.setNatMappingBehavior(limit(report.getNatMappingBehavior(), 80));
        }
        if (report.getNatFilteringBehavior() != null) {
            device.setNatFilteringBehavior(limit(report.getNatFilteringBehavior(), 80));
        }
        if (report.getNatBehaviorDiscovery() != null) {
            device.setNatBehaviorDiscovery(limit(report.getNatBehaviorDiscovery(), 40));
        }
        if (report.getLastEndpoint() != null) {
            device.setLastEndpoint(limit(report.getLastEndpoint(), 255));
        }
        device.setLastSeenAt(now.toString());
        device.setUpdatedAt(now.toString());
        return toDeviceView(deviceRepository.save(device));
    }

    private boolean hasVirtualDeviceReport(PeerControlMessage report) {
        return report.getVirtualDeviceMode() != null
                || report.getVirtualDeviceName() != null
                || report.getVirtualDeviceStatus() != null
                || report.getVirtualDeviceError() != null;
    }

    @Transactional
    public void recordRelayTraffic(long sessionId, long bytes) {
        if (sessionId <= 0 || bytes <= 0) {
            return;
        }
        sessionRepository.lockCurrent(sessionId).ifPresent(session -> {
            Instant now = Instant.now();
            if (!closeIfExpired(session, now)) {
                applyTraffic(session, 0, bytes, now);
            }
            sessionRepository.saveCurrent(session);
        });
    }

    @Transactional
    public boolean authorizeRelayFrame(PeerDataFrameHeader header,
                                       long fromClientId,
                                       long toClientId,
                                       long bytes) {
        if (header == null || fromClientId <= 0 || toClientId <= 0 || bytes <= 0) {
            return false;
        }
        return lockPeerSession(header.sessionId(), null, true)
                .map(current -> {
                    if (!current.allowed()) { markClosed(current.row(), Instant.now()); sessionRepository.saveCurrent(current.row()); return false; }
                    return authorizeRelayFrame(current.row(), fromClientId, toClientId, bytes, Instant.now());
                })
                .orElse(false);
    }

    public boolean authorizeRelayFrameForRelay(PeerDataFrameHeader header,
                                               long fromClientId,
                                               long toClientId,
                                               long bytes) {
        if (header == null || !validRelayPeers(fromClientId, toClientId) || bytes <= 0) {
            return false;
        }
		return authorizeRelayFrameForRelay(header, fromClientId, toClientId, bytes, true);
	}

	public boolean validateRelayFrameForRelay(PeerDataFrameHeader header,
                                            long fromClientId,
                                            long toClientId) {
		return header != null && validRelayPeers(fromClientId, toClientId)
                && authorizeRelayFrameForRelay(header, fromClientId, toClientId, 0L, false);
	}

    /**
     * 允许两种取值：双方都有身份（TURN 认证开启），或双方都是 0（认证关闭，调用方无法确定身份）。
     * 只有一侧为 0 属于调用方错误，一律拒绝。
     */
    private boolean validRelayPeers(long fromClientId, long toClientId) {
        return (fromClientId > 0 && toClientId > 0) || (fromClientId == 0 && toClientId == 0);
    }

	private boolean authorizeRelayFrameForRelay(PeerDataFrameHeader header,
                                               long fromClientId,
                                               long toClientId,
                                               long bytes,
                                               boolean account) {
        long nowNanos = System.nanoTime();
        long nowMillis = System.currentTimeMillis();
        RelayAuthorization cached = relayAuthorizationCache.get(header.sessionId());
        if (cached != null && cached.validAt(nowNanos, nowMillis)) {
            if (!cached.matches(fromClientId, toClientId)) {
                return false;
            }
			if (account) {
				afterCommit(() -> recordPendingRelayBytes(header.sessionId(), bytes));
			}
            return true;
        }
		return authorizeRelayFrameForRelaySlow(
                header, fromClientId, toClientId, bytes, nowNanos, account);
    }

    public boolean authorizeRelayProbeForRelay(PeerUdpProbe probe) {
        if (probe == null
                || probe.getSessionId() == null
                || probe.getSessionId() <= 0
                || probe.getFromClientId() == null
                || probe.getFromClientId() <= 0
                || probe.getToClientId() == null
                || probe.getToClientId() <= 0
                || !StringUtils.hasText(probe.getToken())
                || !(PeerUdpProbe.TYPE_CHECK.equals(probe.getType())
                || PeerUdpProbe.TYPE_CHECK_RESPONSE.equals(probe.getType()))) {
            return false;
        }
        Boolean allowed = transactionTemplate.execute(status -> lockPeerSession(probe.getSessionId(), null, true)
                .map(current -> {
                    if (!current.allowed()) { markClosed(current.row(), Instant.now()); sessionRepository.saveCurrent(current.row()); return false; }
                    return authorizeRelayProbe(current.row(), probe, Instant.now());
                })
                .orElse(false));
        return Boolean.TRUE.equals(allowed);
    }

    private boolean authorizeRelayProbe(PeerMeshSession session, PeerUdpProbe probe, Instant now) {
        if (closeIfExpired(session, now)) {
            sessionRepository.saveCurrent(session);
            return false;
        }
        boolean forward = Objects.equals(probe.getFromClientId(), session.getSourceClientId())
                && Objects.equals(probe.getToClientId(), session.getTargetClientId());
        boolean reverse = Objects.equals(probe.getFromClientId(), session.getTargetClientId())
                && Objects.equals(probe.getToClientId(), session.getSourceClientId());
        if ((!forward && !reverse) || STATUS_CLOSED.equals(session.getStatus())) {
            return false;
        }
        String expected = session.getTokenHash();
        String actual = HexFormat.of().formatHex(HmacSigner.sha256(probe.getToken()));
        return StringUtils.hasText(expected) && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                actual.getBytes(StandardCharsets.US_ASCII));
    }

	protected boolean authorizeRelayFrameForRelaySlow(PeerDataFrameHeader header,
                                                     long fromClientId,
                                                     long toClientId,
                                                     long bytes,
                                                     long nowNanos) {
		return authorizeRelayFrameForRelaySlow(
                header, fromClientId, toClientId, bytes, nowNanos, true);
	}

	private boolean authorizeRelayFrameForRelaySlow(PeerDataFrameHeader header,
                                                   long fromClientId,
                                                   long toClientId,
                                                   long bytes,
                                                   long nowNanos,
												 boolean account) {
        SessionCachePublication publication = new SessionCachePublication(header.sessionId(), null);
        try {
            Boolean allowed = transactionTemplate.execute(status -> lockPeerSession(header.sessionId(), null, true)
                    .map(current -> {
                        if (!current.allowed()) { markClosed(current.row(), Instant.now()); sessionRepository.saveCurrent(current.row()); return false; }
                        return authorizeRelayFrameForRelaySlow(current.row(), header, fromClientId, toClientId, bytes, nowNanos, account, publication);
                    })
                    .orElse(false));
            return Boolean.TRUE.equals(allowed);
        } finally { publication.discardIfUnsubmitted(); }
    }

    private boolean authorizeRelayFrameForRelaySlow(PeerMeshSession session,
                                                     PeerDataFrameHeader header,
                                                     long fromClientId,
                                                     long toClientId,
                                                     long bytes,
													 long nowNanos,
													 boolean account,
                                                     SessionCachePublication publication) {
        Instant now = Instant.now();
        if (closeIfExpired(session, now)) {
            sessionRepository.saveCurrent(session);
            afterCommit(() -> evictClosedSession(header.sessionId()));
            return false;
        }
        if (!matchesSessionPeers(session, fromClientId, toClientId)) {
            invalidateRelayAuthorization(header.sessionId());
            return false;
        }
        // 首个通过身份校验的中继业务帧隐式激活 NEGOTIATING 会话。
        //
        // 探针在 NEGOTIATING 就放行，业务帧却要求 ACTIVE，而 ACTIVE 只能由客户端的
        // path-report 经控制连接异步写入。两者之间必然存在时间窗：客户端探测成功后会立刻
        // flush 待发数据，这些帧会先于 path-report 到达并被丢弃；peer 应用消息没有重传，
        // 一帧丢失就表现为"中继已连通但文件发送失败"。会话身份（双方 clientId + 未过期 +
        // 未关闭）此时已完成校验，等待一条状态上报并不能提供额外安全性，只会制造竞态。
        if (!STATUS_ACTIVE.equals(session.getStatus())) {
            if (STATUS_CLOSED.equals(session.getStatus())) {
                afterCommit(() -> evictClosedSession(header.sessionId()));
                return false;
            }
            session.setStatus(STATUS_ACTIVE);
            session.setPathType(PATH_RELAY);
            session.setUpdatedAt(now.toString());
            session.setLastKeepaliveAt(now.toString());
            sessionRepository.saveCurrent(session);
            log.debug("[peer-mesh] relay frame activated session {}: {} -> {}",
                    session.getId(), STATUS_NEGOTIATING, STATUS_ACTIVE);
        }
        RelayAuthorization authorization = RelayAuthorization.from(session, nowNanos + RELAY_AUTH_CACHE_TTL_NANOS);
        if (!authorization.active()) {
            invalidateRelayAuthorization(header.sessionId());
            return false;
        }
        publication.submit(() -> relayAuthorizationCache.put(header.sessionId(), authorization));
        // A later revocation fences authorization, not accounting for already accepted bytes.
        if (account) afterCommit(() -> recordPendingRelayBytes(header.sessionId(), bytes));
        return true;
    }

    /**
     * 校验帧的双向身份是否与 session 匹配。
     *
     * <p>{@code fromClientId}/{@code toClientId} 为 0 表示调用方无法确定身份（TURN 认证关闭
     * 时 allocation 上没有 clientId）。该模式本身已放弃对端身份保证，这里退化为只校验
     * session 存在且未关闭/未过期，而不是一律拒绝——否则关闭认证会让中继完全不可用。
     */
    private boolean matchesSessionPeers(PeerMeshSession session, long fromClientId, long toClientId) {
        if (fromClientId <= 0 && toClientId <= 0) {
            return true;
        }
        boolean forward = fromClientId == session.getSourceClientId()
                && toClientId == session.getTargetClientId();
        boolean reverse = fromClientId == session.getTargetClientId()
                && toClientId == session.getSourceClientId();
        return forward || reverse;
    }

    @Transactional
    public PeerMeshSessionView closeSession(ClientAccount reporter, PeerControlMessage close) {
        if (close.getSessionId() == null || close.getSessionId() <= 0) {
            throw new IllegalArgumentException("sessionId is required");
        }
        PeerMeshSession session = findReportableSession(reporter, close.getSessionId()).row();
        markClosed(session, Instant.now());
        return toSessionView(sessionRepository.saveCurrent(session));
    }

    @Transactional
    public PeerMeshSessionView closeSession(ManagementContext context, long sessionId) {
        PeerMeshSession session = findAccessibleSession(context, sessionId);
        markClosed(session, Instant.now());
        return toSessionView(sessionRepository.saveCurrent(session));
    }

    @Transactional
    public List<PeerMeshSessionView> closeOpenSessions(ManagementContext context) {
        context = authority.current(context);
        Instant now = Instant.now();
        List<PeerMeshSession> sessions;
        if (context.isAdmin()) {
            sessions = sessionRepository.findByTenantIdAndStatusNotOrderByUpdatedAtDesc(
                    context.tenant().tenantId(), STATUS_CLOSED);
        } else {
            List<Long> visible = visibleClientIds(context);
            if (visible.isEmpty()) {
                return List.of();
            }
            sessions = sessionRepository.findVisibleOpen(
                    context.tenant().tenantId(), visible, STATUS_CLOSED);
        }
        Map<Long, ClientAccount> parents = lockSessionParents(sessions, context.tenant().tenantId());
        ManagementContext actor = context;
        sessions = lockSessionRows(sessions).stream().filter(row -> actor.isAdmin()
                || ownedBy(parents.get(row.getSourceClientId()), actor) || ownedBy(parents.get(row.getTargetClientId()), actor)).toList();
        for (PeerMeshSession session : sessions) {
            markClosed(session, now);
            sessionRepository.saveCurrent(session);
        }
        return sessions.stream().map(this::toSessionView).toList();
    }

    @Transactional
    public List<PeerMeshSessionView> closeOpenSessionsForDevice(ManagementContext context, long clientId) {
        PeerMeshDevice device = findAccessibleDevice(context, clientId);
        return closeOpenSessionsForClient(context.tenant().tenantId(), device.getClientId());
    }

    /** Also closes sessions for a deleted client whose device row was already absent. */
    @Transactional
    public List<PeerMeshSessionView> closeOpenSessionsForClient(String tenantId, long clientId) {
        Instant now = Instant.now();
        List<PeerMeshSession> sessions = sessionRepository.findOpenByClientId(
                tenantId,
                clientId,
                STATUS_CLOSED);
        sessions = lockSessionRows(sessions);
        for (PeerMeshSession session : sessions) {
            markClosedState(session, now);
            sessionRepository.saveCurrent(session);
        }
        if (!sessions.isEmpty()) {
            List<Long> ids = sessions.stream().map(PeerMeshSession::getId).toList();
            afterCommit(() -> ids.forEach(this::evictClosedSession));
        }
        return sessions.stream().map(this::toSessionView).toList();
    }

    @Transactional
    public List<PeerMeshSessionView> closeUnauthorizedSessions(ManagementContext context) {
        // System policy reconciliation after a committed mutation, not a manual close command.
        // A later-disabled request actor must not prevent cleanup of now-unauthorized sessions.
        List<PeerMeshSession> sessions = sessionRepository.findByTenantIdAndStatusNotOrderByUpdatedAtDesc(
                context.tenant().tenantId(), STATUS_CLOSED);
        return closeUnauthorizedSessions(context.tenant().tenantId(), sessions);
    }

    @Transactional
    public List<PeerMeshSessionView> closeUnauthorizedSessionsForClients(String tenant, List<Long> affected) {
        Map<Long, PeerMeshSession> candidates = new java.util.TreeMap<>();
        for (int offset=0; offset<affected.size(); offset+=400)
            for (var session : sessionRepository.findVisibleOpen(tenant, affected.subList(offset, Math.min(offset+400, affected.size())), STATUS_CLOSED))
                candidates.put(session.getId(), session);
        return closeUnauthorizedSessions(tenant, new ArrayList<>(candidates.values()));
    }

    /** A different instance may have closed these rows before the owner of their physical sockets
     * consumes the journal. Replay only authoritative CLOSED grants, not historical owner values.
     * No wall-clock cutoff (cluster clocks can differ); IDs are immutable and a closed grant is
     * never reused. Chunking bounds SQL parameters without truncating large transfer groups. */
    @Transactional(readOnly = true)
    public List<PeerMeshSessionView> closedSessionsForClients(String tenant, List<Long> affected) {
        Map<Long, PeerMeshSession> closed = new java.util.TreeMap<>();
        for (int offset=0; offset<affected.size(); offset+=400)
            for (var session : sessionRepository.findVisibleClosed(tenant, affected.subList(offset, Math.min(offset+400, affected.size())), STATUS_CLOSED))
                closed.put(session.getId(), session);
        return closed.values().stream().map(this::toSessionView).toList();
    }

    private List<PeerMeshSessionView> closeUnauthorizedSessions(String tenant, List<PeerMeshSession> sessions) {
        List<PeerMeshSession> closed = new ArrayList<>();
        Instant now = Instant.now();
        Map<Long, ClientAccount> parents = lockSessionParents(sessions, tenant);
        for (PeerMeshSession session : lockSessionRows(sessions)) {
            if (!canPeerLocked(parents.get(session.getSourceClientId()), parents.get(session.getTargetClientId()))) {
                markClosed(session, now);
                sessionRepository.saveCurrent(session);
                closed.add(session);
            }
        }
        return closed.stream().map(this::toSessionView).toList();
    }

    @Transactional
    public List<PeerMeshSessionView> listSessions(ManagementContext context, int limit) {
        expireIfStale();
        int pageSize = Math.clamp(limit, 1, 200);
        List<PeerMeshSession> sessions;
        if (context.isAdmin()) {
            sessions = sessionRepository.findByTenantIdOrderByUpdatedAtDesc(
                    context.tenant().tenantId(), PageRequest.of(0, pageSize)).getContent();
        } else {
            List<Long> visible = visibleClientIds(context);
            if (visible.isEmpty()) {
                return List.of();
            }
            sessions = sessionRepository.findVisible(
                    context.tenant().tenantId(), visible, PageRequest.of(0, pageSize)).getContent();
        }
        return sessions.stream().map(this::toSessionView).toList();
    }

    @Transactional
    public PeerMeshSessionPage listSessionsPage(ManagementContext context, int page, int size, boolean openOnly) {
        expireIfStale();
        int normalizedPage = Math.max(0, page);
        int normalizedSize = Math.clamp(size, 1, 100);
        PageRequest pageRequest = PageRequest.of(normalizedPage, normalizedSize);
        Page<PeerMeshSession> sessions;
        if (context.isAdmin()) {
            sessions = openOnly
                    ? sessionRepository.findByTenantIdAndStatusNotOrderByUpdatedAtDesc(
                            context.tenant().tenantId(), STATUS_CLOSED, pageRequest)
                    : sessionRepository.findByTenantIdOrderByUpdatedAtDesc(
                            context.tenant().tenantId(), pageRequest);
        } else {
            List<Long> visible = visibleClientIds(context);
            if (visible.isEmpty()) {
                return new PeerMeshSessionPage(List.of(), 0, normalizedPage, normalizedSize, 1);
            }
            sessions = openOnly
                    ? sessionRepository.findVisibleOpenPage(
                            context.tenant().tenantId(), visible, STATUS_CLOSED, pageRequest)
                    : sessionRepository.findVisible(
                            context.tenant().tenantId(), visible, pageRequest);
        }
        return new PeerMeshSessionPage(
                sessions.getContent().stream().map(this::toSessionView).toList(),
                sessions.getTotalElements(),
                normalizedPage,
                normalizedSize,
                Math.max(1, sessions.getTotalPages())
        );
    }

    /**
     * 打洞/路径聚合统计。可见性与 listSessions 一致：admin 看全租户，普通用户只看
     * 自己客户端参与的会话与自己名下设备的 NAT 分布。
     */
    @Transactional
    public PeerMeshPathStatsView pathStats(ManagementContext context) {
        expireIfStale();
        List<PeerMeshSessionRepository.PathTypeAggregate> aggregates;
        List<PeerMeshSessionRepository.AddressFamilyAggregate> addressFamilyAggregates;
        List<PeerMeshDeviceRepository.NatTypeAggregate> natAggregates;
        List<PeerMeshDeviceRepository.NatBehaviorAggregate> natBehaviorAggregates;
        if (context.isAdmin()) {
            aggregates = sessionRepository.aggregatePathTypes(context.tenant().tenantId());
            addressFamilyAggregates = sessionRepository.aggregateAddressFamilies(
                    context.tenant().tenantId());
            natAggregates = deviceRepository.aggregateNatTypes(context.tenant().tenantId());
            natBehaviorAggregates =
                    deviceRepository.aggregateNatBehaviors(context.tenant().tenantId());
        } else {
            List<Long> visible = visibleClientIds(context);
            aggregates = visible.isEmpty()
                    ? List.of()
                    : sessionRepository.aggregateVisiblePathTypes(context.tenant().tenantId(), visible);
            addressFamilyAggregates = visible.isEmpty()
                    ? List.of()
                    : sessionRepository.aggregateVisibleAddressFamilies(
                            context.tenant().tenantId(), visible);
            natAggregates = deviceRepository.aggregateNatTypesByOwner(
                    context.tenant().tenantId(), context.username());
            natBehaviorAggregates = deviceRepository.aggregateNatBehaviorsByOwner(
                    context.tenant().tenantId(), context.username());
        }
        long total = 0;
        long reported = 0;
        long active = 0;
        long activeDirect = 0;
        long activeRelay = 0;
        List<PeerMeshPathStatsView.PathTypeStat> pathTypes = new ArrayList<>();
        for (PeerMeshSessionRepository.PathTypeAggregate aggregate : aggregates) {
            total += aggregate.getSessions();
            reported += aggregate.getReportedSessions();
            if (STATUS_ACTIVE.equals(aggregate.getStatus())) {
                active += aggregate.getSessions();
                if (PATH_DIRECT.equals(aggregate.getPathType())) {
                    activeDirect += aggregate.getSessions();
                } else if (PATH_RELAY.equals(aggregate.getPathType())) {
                    activeRelay += aggregate.getSessions();
                }
            }
            pathTypes.add(new PeerMeshPathStatsView.PathTypeStat(
                    aggregate.getPathType(),
                    aggregate.getStatus(),
                    aggregate.getSessions(),
                    aggregate.getReportedSessions(),
                    aggregate.getAvgRttMillis(),
                    aggregate.getDirectBytes(),
                    aggregate.getRelayBytes()));
        }
        // 空串与 null 的 natType 归并为 UNKNOWN
        Map<String, Long> natCounts = new LinkedHashMap<>();
        for (PeerMeshDeviceRepository.NatTypeAggregate item : natAggregates) {
            String key = StringUtils.hasText(item.getNatType()) ? item.getNatType() : "UNKNOWN";
            natCounts.merge(key, item.getDevices(), Long::sum);
        }
        List<PeerMeshPathStatsView.NatTypeStat> natTypes = natCounts.entrySet().stream()
                .map(entry -> new PeerMeshPathStatsView.NatTypeStat(entry.getKey(), entry.getValue()))
                .toList();
        long natBehaviorDevices = 0;
        long natBehaviorClassifiedDevices = 0;
        Map<String, Long> mappingCounts = new LinkedHashMap<>();
        Map<String, Long> filteringCounts = new LinkedHashMap<>();
        Map<String, Long> discoveryCounts = new LinkedHashMap<>();
        for (PeerMeshDeviceRepository.NatBehaviorAggregate item : natBehaviorAggregates) {
            if (!StringUtils.hasText(item.getMappingBehavior())
                    && !StringUtils.hasText(item.getFilteringBehavior())
                    && !StringUtils.hasText(item.getDiscovery())) {
                continue;
            }
            long devices = item.getDevices();
            natBehaviorDevices += devices;
            String mapping = normalizeNatBehavior(item.getMappingBehavior());
            String filtering = normalizeNatBehavior(item.getFilteringBehavior());
            String discovery = normalizeNatBehavior(item.getDiscovery());
            mappingCounts.merge(mapping, devices, Long::sum);
            filteringCounts.merge(filtering, devices, Long::sum);
            discoveryCounts.merge(discovery, devices, Long::sum);
            if (isClassifiedNatBehavior(mapping) && isClassifiedNatBehavior(filtering)) {
                natBehaviorClassifiedDevices += devices;
            }
        }
        List<PeerMeshPathStatsView.AddressFamilyStat> addressFamilies = addressFamilyAggregates.stream()
                .map(item -> new PeerMeshPathStatsView.AddressFamilyStat(
                        item.getAddressFamily(),
                        item.getStatus(),
                        item.getPathType(),
                        item.getSessions(),
                        item.getReportedSessions()))
                .toList();
        return new PeerMeshPathStatsView(
                total,
                reported,
                active,
                activeDirect,
                activeRelay,
                active == 0 ? null : (double) activeDirect / active,
                pathTypes,
                addressFamilies,
                natTypes,
                natBehaviorDevices,
                natBehaviorClassifiedDevices,
                natBehaviorDevices == 0
                        ? null
                        : (double) natBehaviorClassifiedDevices / natBehaviorDevices,
                natBehaviorStats(mappingCounts),
                natBehaviorStats(filteringCounts),
                natBehaviorStats(discoveryCounts));
    }

    private List<PeerMeshPathStatsView.NatBehaviorStat> natBehaviorStats(
            Map<String, Long> counts) {
        return counts.entrySet().stream()
                .map(entry -> new PeerMeshPathStatsView.NatBehaviorStat(
                        entry.getKey(),
                        entry.getValue()))
                .toList();
    }

    private String normalizeNatBehavior(String value) {
        return StringUtils.hasText(value) ? value.trim() : "UNKNOWN";
    }

    private boolean isClassifiedNatBehavior(String value) {
        return StringUtils.hasText(value)
                && !"UNKNOWN".equalsIgnoreCase(value)
                && !"UNSUPPORTED".equalsIgnoreCase(value);
    }

    private List<Long> visibleClientIds(ManagementContext context) {
        return clientAccountRepository
                .findByTenantIdAndOwnerUsernameOrderByIdDesc(context.tenant().tenantId(), context.username())
                .stream()
                .map(ClientAccount::getId)
                .toList();
    }

    @Scheduled(fixedDelayString = "${specus.peer-mesh.session-cleanup-interval-ms:60000}")
    @Transactional
    public void expireStaleSessions() {
        expireStaleSessionsBatch(Instant.now(), 500);
    }

    @Scheduled(fixedDelayString = "${specus.peer-mesh.relay-traffic-flush-interval-ms:5000}")
    public void flushRelayTraffic() {
        if (pendingRelayBytes.isEmpty()) {
            return;
        }
        pendingRelayBytes.forEach((sessionId, counter) -> {
            long bytes = counter.getAndSet(0);
            if (bytes <= 0) {
                return;
            }
            AtomicBoolean restored = new AtomicBoolean();
            Runnable restore = () -> { if (restored.compareAndSet(false, true)) restoreRelayTrafficBatch(sessionId, bytes); };
            try {
                RelayTrafficFlushResult result = transactionTemplate.execute(status -> {
                    if (TransactionSynchronizationManager.isSynchronizationActive())
                        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                            @Override public void afterCompletion(int completion) { if (completion != STATUS_COMMITTED) restore.run(); }
                        });
                    return persistRelayTrafficBatch(sessionId, bytes, Instant.now());
                });
                if (result == null) {
                    throw new IllegalStateException("relay traffic transaction returned no result");
                }
                afterCommit(() -> {
                    lastRelayTrafficFlushSuccessMillis.set(System.currentTimeMillis());
                    if (result == RelayTrafficFlushResult.MISSING) {
                        evictClosedSession(sessionId);
                        pendingRelayBytes.remove(sessionId, counter);
                    } else if (result == RelayTrafficFlushResult.CLOSED) {
                        evictClosedSession(sessionId);
                        pendingRelayBytes.computeIfPresent(sessionId, (ignored, current) ->
                                current == counter && current.get() == 0 ? null : current);
                    }
                });
            } catch (RuntimeException e) {
                restore.run();
                relayTrafficFlushFailures.increment();
                log.warn("Peer mesh relay traffic flush failed: session={}, bytes={}, reason={}",
                        sessionId, bytes, e.getMessage());
            }
        });
    }

    private RelayTrafficFlushResult persistRelayTrafficBatch(long sessionId, long bytes, Instant now) {
        Optional<PeerMeshSession> found = sessionRepository.lockCurrent(sessionId);
        if (found.isEmpty()) {
            return RelayTrafficFlushResult.MISSING;
        }
        PeerMeshSession session = found.get();
        boolean expired = closeIfExpired(session, now);
        applyTraffic(session, 0, bytes, now);
        sessionRepository.saveCurrent(session);
        return expired ? RelayTrafficFlushResult.CLOSED : RelayTrafficFlushResult.PERSISTED;
    }

    private void restoreRelayTrafficBatch(long sessionId, long bytes) {
        pendingRelayBytes.compute(sessionId, (ignored, current) -> {
            AtomicLong counter = current == null ? new AtomicLong() : current;
            counter.addAndGet(bytes);
            return counter;
        });
    }

    private double pendingRelayByteCount() {
        long total = 0;
        for (AtomicLong counter : pendingRelayBytes.values()) {
            long value = counter.get();
            if (value > Long.MAX_VALUE - total) {
                return Long.MAX_VALUE;
            }
            total += value;
        }
        return total;
    }

    @Transactional(readOnly = true)
    public List<PeerRosterItem> allowedRoster(ClientAccount account) {
        if (!properties.isEnabled()) {
            return List.of();
        }
        var snapshot = readPeers(account);
        return snapshot.edges().stream()
                .filter(edge -> edge.target().id() != snapshot.source().id() && edge.outgoing(snapshot.tenant()))
                .map(PeerReadSnapshotRepository.Edge::target)
                .sorted(java.util.Comparator.comparing(PeerReadSnapshotRepository.Peer::name)
                        .thenComparingLong(PeerReadSnapshotRepository.Peer::id))
                .map(peer -> {
                    var binding = boundPeer(snapshot, peer);
                    var session = binding.capabilities();
                    boolean online = binding.online();
                    return new PeerRosterItem(
                            peer.id(),
                            peer.name(),
                            peer.virtualIp(),
                            peer.publicKey(),
                            online,
                            online && session != null && session.send(),
                            online && session != null && session.receive(),
                            online && session != null && session.attachments(),
                            online && session != null && session.media(),
                            online && session != null ? session.maxBytes() : 0,
                            online && session != null ? session.discoveryVersion() : 0,
                            online && session != null
                                    ? PeerServiceDiscovery.decodeApplications(session.applications())
                                    : List.of());
                })
                .toList();
    }

    private PeerReadSnapshotRepository.Snapshot readPeers(ClientAccount account) {
        return account == null || account.getId() == null || account.getTenantId() == null
                ? PeerReadSnapshotRepository.Snapshot.empty(null) : peerReads.read(account.getTenantId(), account.getId());
    }

    private io.netty.channel.Channel boundChannel(String tenant, PeerReadSnapshotRepository.Peer peer) {
        if (peer == null || !peer.available(tenant)) return null;
        var channel = SessionUtil.getChannel(peer.name());
        var session = channel == null ? null : SessionUtil.getSession(channel);
        return channel != null && channel.isActive() && session != null && peer.name().equals(session.getClientName())
                && tenant.equals(channel.attr(ServerAttributes.TENANT_ID).get()) ? channel : null;
    }

    private PeerReadSnapshotRepository.Capabilities boundCapabilities(PeerReadSnapshotRepository.Snapshot snapshot,
                                                                      PeerReadSnapshotRepository.Peer peer) {
        return boundPeer(snapshot, peer).capabilities();
    }

    private record BoundPeer(boolean online, PeerReadSnapshotRepository.Capabilities capabilities) {}

    private BoundPeer boundPeer(PeerReadSnapshotRepository.Snapshot snapshot, PeerReadSnapshotRepository.Peer peer) {
        var channel = boundChannel(snapshot.tenant(), peer);
        var id = channel == null ? null : channel.attr(ServerAttributes.CLIENT_SESSION_ID).get();
        var capabilities = id == null ? null : snapshot.sessions().getOrDefault(peer.id(), List.of()).stream()
                .filter(row -> row.sessionId() == id).findFirst().orElse(null);
        boolean current = channel != null && channel.isActive() && SessionUtil.getChannel(peer.name()) == channel;
        return new BoundPeer(current && (id == null || capabilities != null), current ? capabilities : null);
    }

    @Transactional(readOnly = true)
    public List<ClientAccount> rosterRefreshTargets(ClientAccount account) {
        if (account == null) {
            return List.of();
        }
        return clientAccountRepository.findByTenantIdOrderByIdDesc(account.getTenantId());
    }

    private ClientAccount lockRuntimeClient(ClientAccount reference) {
        if (reference == null || reference.getId() == null || reference.getTenantId() == null)
            throw new IllegalArgumentException("client identity is required");
        return clientAccountRepository.lockCurrent(reference.getId(), reference.getTenantId())
                .filter(ClientAccount::isEnabled)
                .orElseThrow(() -> new IllegalArgumentException("client unavailable: " + reference.getId()));
    }

    private PeerMeshDevice currentDevice(ClientAccount account) {
        // A current client row serializes device creation and metadata writers for that client.
        // Never return a JPA cached device that can restore an old enabled/IP/owner state.
        return deviceRepository.lockCurrent(account.getTenantId(), account.getId())
                .orElseGet(() -> deviceRepository.save(createDevice(account)));
    }

    private PeerMeshDevice createDevice(ClientAccount account) {
        String now = Instant.now().toString();
        PeerMeshDevice device = new PeerMeshDevice();
        device.setId(ClientIdGenerator.newId());
        device.setTenantId(account.getTenantId());
        device.setOwnerUsername(normalizeOwner(account.getOwnerUsername()));
        device.setClientId(account.getId());
        device.setClientName(account.getClientName());
        device.setVirtualIp(allocateVirtualIp(account));
        device.setCidr(properties.getCidr());
        device.setEnabled(false);
        device.setCreatedAt(now);
        device.setUpdatedAt(now);
        return device;
    }

    private String allocateVirtualIp(ClientAccount account) {
        int base = ipv4ToInt(properties.getCidr().split("/", 2)[0]);
        int prefix = Integer.parseInt(properties.getCidr().split("/", 2)[1]);
        int capacity = 1 << Math.max(0, 32 - prefix);
        int seed = Math.abs((account.getTenantId() + ":" + account.getOwnerUsername() + ":" + account.getId()).hashCode());
        for (int i = 1; i < Math.max(2, capacity - 1); i++) {
            int host = (seed + i) % Math.max(2, capacity - 2) + 1;
            String ip = intToIpv4(base + host);
            Optional<PeerMeshDevice> existing = deviceRepository.findByTenantIdAndVirtualIp(account.getTenantId(), ip);
            if (existing.isEmpty()) {
                return ip;
            }
        }
        throw new IllegalStateException("peer mesh address pool exhausted: " + properties.getCidr());
    }

    private PeerMeshDevice findAccessibleDevice(ManagementContext context, long clientId) {
        return deviceRepository.findByTenantIdAndClientId(context.tenant().tenantId(), clientId)
                .filter(device -> context.isAdmin() || device.getOwnerUsername().equals(context.username()))
                .orElseThrow(() -> new IllegalArgumentException("peer device not found: " + clientId));
    }

    private ClientAccount findAccessibleClient(ManagementContext context, long clientId) {
        return (context.isAdmin()
                ? clientAccountRepository.findByIdAndTenantId(clientId, context.tenant().tenantId())
                : clientAccountRepository.findByIdAndTenantIdAndOwnerUsername(
                        clientId, context.tenant().tenantId(), context.username()))
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + clientId));
    }

    private ClientAccount findTenantClient(ManagementContext context, long clientId) {
        return clientAccountRepository.findByIdAndTenantId(clientId, context.tenant().tenantId())
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + clientId));
    }

    private PeerMeshDeviceView toDeviceView(PeerMeshDevice device) {
        return new PeerMeshDeviceView(
                device.getId(),
                device.getClientId(),
                device.getClientName(),
                device.getOwnerUsername(),
                device.isEnabled(),
                SessionUtil.getChannel(device.getClientName()) != null,
                device.getVirtualIp(),
                device.getCidr(),
                device.getPublicKey(),
                device.getNatType(),
                device.getNatMappingBehavior(),
                device.getNatFilteringBehavior(),
                device.getNatBehaviorDiscovery(),
                device.getLastEndpoint(),
                device.getVirtualDeviceMode(),
                device.getVirtualDeviceName(),
                device.getVirtualDeviceStatus(),
                device.getVirtualDeviceError(),
                device.getVirtualDeviceUpdatedAt(),
                device.getLastSeenAt(),
                device.getUpdatedAt()
        );
    }

    private PeerMeshAclView toAclView(PeerMeshAcl acl) {
        return new PeerMeshAclView(
                acl.getId(),
                acl.getSourceClientId(),
                acl.getSourceClientName(),
                acl.getTargetClientId(),
                acl.getTargetClientName(),
                acl.isAllowed(),
                acl.getDirection(),
                acl.getCreatedAt(),
                acl.getUpdatedAt()
        );
    }

    private PeerMeshSessionView toSessionView(PeerMeshSession session) {
        return new PeerMeshSessionView(
                session.getId(),
                session.getSourceClientId(),
                session.getSourceClientName(),
                session.getTargetClientId(),
                session.getTargetClientName(),
                effectivePathType(session),
                session.getStatus(),
                session.getRttMillis(),
                session.getLocalEndpoint(),
                session.getRemoteEndpoint(),
                session.getDirectBytes(),
                session.getRelayBytes(),
                session.getLastTrafficAt(),
                session.getLastKeepaliveAt(),
                session.getStartedAt(),
                session.getUpdatedAt(),
                SortableInstant.toInstantString(session.getExpiresAt()),
                session.getClosedAt()
        );
    }

    private String effectivePathType(PeerMeshSession session) {
        if (session == null) {
            return PATH_DIRECT;
        }
        if (session.getRelayBytes() > session.getDirectBytes()) {
            return PATH_RELAY;
        }
        if (session.getDirectBytes() > session.getRelayBytes()) {
            return PATH_DIRECT;
        }
        return StringUtils.hasText(session.getPathType()) ? session.getPathType() : PATH_DIRECT;
    }

    private String resolvePeerHost(String requestServerName) {
        if (StringUtils.hasText(properties.getPublicAddress())) {
            return properties.getPublicAddress().trim();
        }
        return StringUtils.hasText(requestServerName) ? requestServerName.trim() : "";
    }

    private String resolveStunHost(String requestServerName) {
        if (hasStandaloneStun()) {
            return properties.getStandaloneStunAddress().trim();
        }
        return resolvePeerHost(requestServerName);
    }

    private int resolveStunPort() {
        return hasStandaloneStun()
                ? properties.getStandaloneStunPort()
                : properties.getStunTurnPort();
    }

    private boolean hasStandaloneStun() {
        return StringUtils.hasText(properties.getStandaloneStunAddress())
                && properties.getStandaloneStunPort() > 0;
    }

    private List<String> publicStunServers() {
        LinkedHashSet<String> servers = new LinkedHashSet<>();
        if (StringUtils.hasText(properties.getStandaloneStunAlternateAddress())
                && resolveStunPort() > 0) {
            String host = properties.getStandaloneStunAlternateAddress().trim();
            servers.add("stun:" + bracketIpv6(host) + ":" + resolveStunPort());
        }
        if (properties.getPublicStunServers() != null) {
            properties.getPublicStunServers().stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .forEach(servers::add);
        }
        return servers.stream()
                .limit(16)
                .toList();
    }

    private String bracketIpv6(String host) {
        return host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
    }

    private record CurrentPeerSession(PeerMeshSession row, Map<Long, ClientAccount> parents, boolean allowed) {}

    private Optional<CurrentPeerSession> lockPeerSession(long id, String requiredTenant, boolean checkPolicy) {
        var hint = sessionRepository.findReference(id).filter(row -> requiredTenant == null || requiredTenant.equals(row.tenant()));
        if (hint.isEmpty()) return Optional.empty();
        var reference = hint.get();
        Map<Long, ClientAccount> parents = clientAccountRepository.lockCurrentAll(List.of(reference.source(), reference.target()), reference.tenant());
        boolean allowed = checkPolicy && canPeerLocked(parents.get(reference.source()), parents.get(reference.target()));
        return sessionRepository.lockCurrent(id).filter(row -> row.getTenantId().equals(reference.tenant())
                        && row.getSourceClientId() == reference.source() && row.getTargetClientId() == reference.target())
                .map(row -> new CurrentPeerSession(row, parents, allowed));
    }

    private CurrentPeerSession findReportableSession(ClientAccount reporter, long sessionId) {
        if (reporter == null || reporter.getId() == null || reporter.getTenantId() == null)
            throw new IllegalArgumentException("peer session report source mismatch");
        CurrentPeerSession current = lockPeerSession(sessionId, reporter.getTenantId(), true)
                .orElseThrow(() -> new IllegalArgumentException("peer session not found: " + sessionId));
        PeerMeshSession session = current.row();
        boolean reporterInSession = reporter.getId().equals(session.getSourceClientId())
                || reporter.getId().equals(session.getTargetClientId());
        ClientAccount actor = current.parents().get(reporter.getId());
        if (!reporterInSession || actor == null || !actor.isEnabled()) {
            throw new IllegalArgumentException("peer session report source mismatch");
        }
        return current;
    }

    private PeerMeshSession findAccessibleSession(ManagementContext context, long sessionId) {
        ManagementContext actor = authority.current(context);
        CurrentPeerSession current = lockPeerSession(sessionId, actor.tenant().tenantId(), false)
                .orElseThrow(() -> new IllegalArgumentException("peer session not found: " + sessionId));
        if (actor.isAdmin() || ownedBy(current.parents().get(current.row().getSourceClientId()), actor)
                || ownedBy(current.parents().get(current.row().getTargetClientId()), actor)) {
            return current.row();
        }
        throw new IllegalArgumentException("peer session not found: " + sessionId);
    }

    private boolean ownedBy(ClientAccount row, ManagementContext actor) {
        return row != null && actor.username().equals(normalizeOwner(row.getOwnerUsername()));
    }

    private Map<Long, ClientAccount> lockSessionParents(List<PeerMeshSession> hints, String tenant) {
        List<Long> ids = hints.stream().flatMap(row -> java.util.stream.Stream.of(row.getSourceClientId(), row.getTargetClientId())).distinct().sorted().toList();
        return clientAccountRepository.lockCurrentAll(ids, tenant);
    }

    /** Discovery is not current authority. Lock by globally ordered primary keys, never a
     * missing-pair range (InnoDB gap locks), and never mutate a cached JPA discovery entity. */
    private List<PeerMeshSession> lockSessionRows(List<PeerMeshSession> hints) {
        Map<Long, PeerMeshSession> byId = hints.stream().collect(Collectors.toMap(PeerMeshSession::getId, row -> row, (a,b) -> a));
        List<PeerMeshSession> result = new ArrayList<>();
        for (Long id : byId.keySet().stream().sorted().toList()) {
            var old = byId.get(id);
            sessionRepository.lockCurrent(id).filter(row -> Objects.equals(row.getTenantId(), old.getTenantId())
                    && Objects.equals(row.getSourceClientId(), old.getSourceClientId()) && Objects.equals(row.getTargetClientId(), old.getTargetClientId()))
                    .ifPresent(row -> {
                        if (STATUS_CLOSED.equals(row.getStatus())) afterCommit(() -> evictClosedSession(row.getId()));
                        else result.add(row);
                    });
        }
        return result;
    }

    private void applyTraffic(PeerMeshSession session, long directBytes, long relayBytes, Instant now) {
        if (directBytes <= 0 && relayBytes <= 0) {
            return;
        }
        session.setDirectBytes(saturatedAdd(session.getDirectBytes(), directBytes));
        session.setRelayBytes(saturatedAdd(session.getRelayBytes(), relayBytes));
        session.setPathType(effectivePathType(session));
        session.setLastTrafficAt(now.toString());
        session.setLastKeepaliveAt(now.toString());
        session.setUpdatedAt(now.toString());
    }

    private boolean authorizeRelayFrame(PeerMeshSession session,
                                        long fromClientId,
                                        long toClientId,
                                        long bytes,
                                        Instant now) {
        if (closeIfExpired(session, now)) {
            sessionRepository.saveCurrent(session);
            return false;
        }
        if (!STATUS_ACTIVE.equals(session.getStatus())) {
            return false;
        }
        boolean forward = fromClientId == session.getSourceClientId()
                && toClientId == session.getTargetClientId();
        boolean reverse = fromClientId == session.getTargetClientId()
                && toClientId == session.getSourceClientId();
        if (!forward && !reverse) {
            return false;
        }
        applyTraffic(session, 0, bytes, now);
        sessionRepository.saveCurrent(session);
        return true;
    }

    private int expireStaleSessionsBatch(Instant now, int limit) {
        List<PeerMeshSession> expired = sessionRepository
                .findByStatusNotAndExpiresAtLessThanEqualOrderByExpiresAtAsc(
                        STATUS_CLOSED,
                        SortableInstant.format(now),
                        PageRequest.of(0, Math.clamp(limit, 1, 1000)));
        expired = lockSessionRows(expired).stream().filter(row -> isExpired(row, now)).toList();
        for (PeerMeshSession session : expired) {
            markClosed(session, now);
            sessionRepository.saveCurrent(session);
        }
        return expired.size();
    }

    private boolean closeIfExpired(PeerMeshSession session, Instant now) {
        if (STATUS_CLOSED.equals(session.getStatus())) {
            afterCommit(() -> evictClosedSession(session.getId()));
            return true;
        }
        if (!isExpired(session, now)) {
            return false;
        }
        markClosed(session, now);
        return true;
    }

    private boolean isExpired(PeerMeshSession session, Instant now) {
        if (!StringUtils.hasText(session.getExpiresAt())) {
            return false;
        }
        try {
            return !Instant.parse(session.getExpiresAt()).isAfter(now);
        } catch (Exception ignored) {
            return false;
        }
    }

    private void markClosed(PeerMeshSession session, Instant now) {
        markClosedState(session, now);
        afterCommit(() -> evictClosedSession(session.getId()));
    }

    private void markClosedState(PeerMeshSession session, Instant now) {
        if (!STATUS_CLOSED.equals(session.getStatus())) {
            session.setStatus(STATUS_CLOSED);
        }
        if (!StringUtils.hasText(session.getClosedAt())) {
            session.setClosedAt(now.toString());
        }
        session.setUpdatedAt(now.toString());
    }

    private void evictClosedSession(Long sessionId) {
        if (sessionId != null) {
            synchronized (sessionCacheMonitor) {
                sessionCacheFences.remove(sessionId);
                relayAuthorizationCache.remove(sessionId);
                sessionTokenCache.remove(sessionId);
                // Accepted bytes are still owed to accounting, even after closure. The flush
                // writer can persist them on a CLOSED row; never discard them on invalidation.
            }
        }
    }

    private void invalidateRelayAuthorization(Long sessionId) {
        afterCommit(() -> {
            synchronized (sessionCacheMonitor) {
                sessionCacheFences.remove(sessionId);
                relayAuthorizationCache.remove(sessionId);
            }
        });
    }

    private void recordPendingRelayBytes(long sessionId, long bytes) {
        pendingRelayBytes.compute(sessionId, (ignored, counter) -> {
            if (counter == null) counter = new AtomicLong();
            counter.addAndGet(bytes); return counter;
        });
    }

    private static void afterCommit(Runnable effect) {
        if (TransactionSynchronizationManager.isSynchronizationActive() && TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCommit() { effect.run(); }
            });
        } else effect.run();
    }

    private String pendingOrCachedSessionToken(long sessionId) {
        if (TransactionSynchronizationManager.isSynchronizationActive())
            for (TransactionSynchronization sync : TransactionSynchronizationManager.getSynchronizations())
                if (sync instanceof SessionCachePublication publication && publication.belongsTo(this)
                        && publication.sessionId == sessionId && publication.token != null) return publication.token;
        return sessionTokenCache.get(sessionId);
    }

    private static final class SessionCacheFence { private int publications; }

    /** Pending tokens live only in this transaction's synchronization list (also isolates REQUIRES_NEW).
     * Fences exist only while a cache entry or pending publication needs them, not per arbitrary ID. */
    private final class SessionCachePublication implements TransactionSynchronization {
        private final long sessionId;
        private final String token;
        private final SessionCacheFence fence;
        private Runnable effect;
        private boolean submitted, completed;
        private SessionCachePublication(long sessionId, String token) {
            this.sessionId = sessionId; this.token = token;
            synchronized (sessionCacheMonitor) {
                fence = sessionCacheFences.computeIfAbsent(sessionId, ignored -> new SessionCacheFence());
                fence.publications++;
            }
        }
        private boolean belongsTo(PeerMeshService owner) { return PeerMeshService.this == owner; }
        private void submit(Runnable effect) {
            this.effect = effect; submitted = true;
            if (TransactionSynchronizationManager.isSynchronizationActive() && TransactionSynchronizationManager.isActualTransactionActive())
                TransactionSynchronizationManager.registerSynchronization(this);
            else {
                try { afterCommit(); } finally { afterCompletion(STATUS_COMMITTED); }
            }
        }
        @Override public void afterCommit() {
            synchronized (sessionCacheMonitor) {
                if (sessionCacheFences.get(sessionId) == fence) effect.run();
            }
        }
        @Override public void afterCompletion(int status) {
            synchronized (sessionCacheMonitor) {
                if (completed) return;
                completed = true; fence.publications--;
                if (fence.publications == 0 && !relayAuthorizationCache.containsKey(sessionId)
                        && !sessionTokenCache.containsKey(sessionId)) sessionCacheFences.remove(sessionId, fence);
            }
        }
        private void discardIfUnsubmitted() { if (!submitted) afterCompletion(STATUS_UNKNOWN); }
    }

    private long saturatedAdd(long current, long delta) {
        if (delta <= 0) {
            return current;
        }
        long next = current + delta;
        return next < 0 ? Long.MAX_VALUE : next;
    }

    private String serverPublicKey() {
        return HexFormat.of().formatHex(HmacSigner.sha256("specus-peer-mesh-server"));
    }

    private String shortToken(String... parts) {
        return PasswordService.generatePassword() + "-" + HexFormat.of().formatHex(HmacSigner.sha256(String.join("\n", parts))).substring(0, 16);
    }

    private long requireId(Long id, String field) {
        if (id == null || id <= 0) {
            throw new IllegalArgumentException(field + " is required");
        }
        return id;
    }

    private String normalizeOwner(String ownerUsername) {
        return StringUtils.hasText(ownerUsername) ? ownerUsername.trim() : "admin";
    }

    private String limit(String value, int max) {
        if (value == null || value.length() <= max) {
            return value;
        }
        return value.substring(0, max);
    }

    private int ipv4ToInt(String value) {
        try {
            byte[] bytes = InetAddress.getByName(value).getAddress();
            return (bytes[0] & 0xFF) << 24
                    | (bytes[1] & 0xFF) << 16
                    | (bytes[2] & 0xFF) << 8
                    | (bytes[3] & 0xFF);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("invalid peer mesh cidr: " + properties.getCidr(), e);
        }
    }

    private String intToIpv4(int value) {
        return ((value >>> 24) & 0xFF) + "."
                + ((value >>> 16) & 0xFF) + "."
                + ((value >>> 8) & 0xFF) + "."
                + (value & 0xFF);
    }

    public record DeviceMutation(Boolean enabled) {
    }

    public record PeerMeshSessionPage(List<PeerMeshSessionView> items,
                                      long total,
                                      int page,
                                      int size,
                                      int totalPages) {
    }

    public record AclMutation(Long sourceClientId, Long targetClientId, Boolean allowed, String direction) {
    }

    public record PeerRosterItem(long clientId,
                                 String clientName,
                                 String virtualIp,
                                 String publicKey,
                                 boolean online,
                                 boolean messageSendCapable,
                                 boolean messageReceiveCapable,
                                 boolean messageAttachmentsCapable,
                                 boolean messageMediaPreviewCapable,
                                 long messageMaxAttachmentBytes,
                                 int peerServiceDiscoveryVersion,
                                 List<String> peerServiceApplications) {
    }

    public record PeerSessionGrant(PeerMeshSessionView session, String token) {
    }

    public record PeerIdentity(String virtualIp, String publicKey) {
    }

    private enum RelayTrafficFlushResult {
        PERSISTED,
        CLOSED,
        MISSING
    }

    private record RelayAuthorization(long sourceClientId,
                                      long targetClientId,
                                      boolean active,
                                      long sessionExpiresAtMillis,
                                      long cacheExpiresAtNanos) {
        private static RelayAuthorization from(PeerMeshSession session, long cacheExpiresAtNanos) {
            return new RelayAuthorization(
                    session.getSourceClientId(),
                    session.getTargetClientId(),
                    STATUS_ACTIVE.equals(session.getStatus()),
                    parseInstantMillis(session.getExpiresAt()),
                    cacheExpiresAtNanos
            );
        }

        private boolean validAt(long nowNanos, long nowMillis) {
            return active && cacheExpiresAtNanos > nowNanos
                    && (sessionExpiresAtMillis <= 0 || sessionExpiresAtMillis > nowMillis);
        }

        /** 0/0 表示调用方无法确定身份（TURN 认证关闭），与慢路径保持一致的降级语义。 */
        private boolean matches(long fromClientId, long toClientId) {
            if (fromClientId <= 0 && toClientId <= 0) {
                return true;
            }
            boolean forward = fromClientId == sourceClientId && toClientId == targetClientId;
            boolean reverse = fromClientId == targetClientId && toClientId == sourceClientId;
            return forward || reverse;
        }

        private static long parseInstantMillis(String value) {
            if (!StringUtils.hasText(value)) {
                return 0;
            }
            try {
                return Instant.parse(value).toEpochMilli();
            } catch (Exception ignored) {
                return 0;
            }
        }
    }

    private void expireIfStale() {
        long now = System.currentTimeMillis();
        if (now - lastExpireMillis > 30_000) {
            lastExpireMillis = now;
            expireStaleSessionsBatch(Instant.now(), 500);
        }
    }
}
