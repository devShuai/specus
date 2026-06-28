package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerDataFrameHeader;
import com.theshuai.common.security.HmacSigner;
import com.theshuai.tunnelserver.config.PeerMeshProperties;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.PeerMeshAcl;
import com.theshuai.tunnelserver.management.model.PeerMeshAclView;
import com.theshuai.tunnelserver.management.model.PeerMeshDevice;
import com.theshuai.tunnelserver.management.model.PeerMeshDeviceView;
import com.theshuai.tunnelserver.management.model.PeerMeshSession;
import com.theshuai.tunnelserver.management.model.PeerMeshSessionView;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshAclRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshSessionRepository;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.security.PasswordService;
import com.theshuai.tunnelserver.session.SessionUtil;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.Collectors;

@Service
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
    private final Map<Long, RelayAuthorization> relayAuthorizationCache = new ConcurrentHashMap<>();
    private final Map<Long, LongAdder> pendingRelayBytes = new ConcurrentHashMap<>();

    public PeerMeshService(PeerMeshProperties properties,
                           PeerMeshDeviceRepository deviceRepository,
                           PeerMeshAclRepository aclRepository,
                           PeerMeshSessionRepository sessionRepository,
                           ClientAccountRepository clientAccountRepository) {
        this.properties = properties;
        this.deviceRepository = deviceRepository;
        this.aclRepository = aclRepository;
        this.sessionRepository = sessionRepository;
        this.clientAccountRepository = clientAccountRepository;
    }

    public boolean isEnabled() {
        return properties.isEnabled();
    }

    @Transactional
    public ClientAuthLoginResponse.PeerMeshConfig buildLoginConfig(ClientAccount account,
                                                                  ClientEnvironmentInfo environment,
                                                                  String requestServerName) {
        PeerMeshDevice device = null;
        if (properties.isEnabled()) {
            device = ensureDevice(account, environment);
        }
        return buildConfig(account, device, requestServerName);
    }

    @Transactional
    public ClientAuthLoginResponse.PeerMeshConfig buildRuntimeConfig(ClientAccount account) {
        PeerMeshDevice device = null;
        if (properties.isEnabled()) {
            device = deviceRepository.findByTenantIdAndClientId(account.getTenantId(), account.getId())
                    .orElseGet(() -> deviceRepository.save(createDevice(account)));
        }
        return buildConfig(account, device, null);
    }

    private ClientAuthLoginResponse.PeerMeshConfig buildConfig(ClientAccount account,
                                                               PeerMeshDevice device,
                                                               String requestServerName) {
        ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
        config.setEnabled(false);
        config.setClientId(account.getId());
        config.setClientName(account.getClientName());
        config.setCidr(properties.getCidr());
        config.setSessionTtlSeconds(properties.getSessionTtlSeconds());
        if (!properties.isEnabled() || device == null) {
            return config;
        }
        config.setEnabled(device.isEnabled());
        config.setVirtualIp(device.getVirtualIp());
        config.setStunHost(resolvePeerHost(requestServerName));
        config.setTurnHost(resolvePeerHost(requestServerName));
        config.setStunPort(properties.getStunTurnPort());
        config.setTurnPort(properties.getStunTurnPort());
        config.setIceUsername("pm-" + account.getId());
        config.setIceCredential(shortToken(account.getTenantId(), account.getClientName(), device.getVirtualIp()));
        config.setServerPublicKey(serverPublicKey());
        config.setClientPublicKey(device.getPublicKey());
        return config;
    }

    @Transactional
    public PeerMeshDevice ensureDevice(ClientAccount account, ClientEnvironmentInfo environment) {
        PeerMeshDevice device = deviceRepository.findByTenantIdAndClientId(account.getTenantId(), account.getId())
                .orElseGet(() -> createDevice(account));
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
        PeerMeshDevice device = findAccessibleDevice(context, clientId);
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
        ClientAccount source = findAccessibleClient(context, requireId(mutation.sourceClientId(), "sourceClientId"));
        ClientAccount target = findTenantClient(context, requireId(mutation.targetClientId(), "targetClientId"));
        if (source.getId().equals(target.getId())) {
            throw new IllegalArgumentException("source and target cannot be the same client");
        }
        if (!context.isAdmin() && !normalizeOwner(target.getOwnerUsername()).equals(context.username())) {
            throw new IllegalArgumentException("普通用户不能创建跨用户 peer ACL");
        }
        PeerMeshAcl acl = aclRepository.findByTenantIdAndSourceClientIdAndTargetClientId(
                context.tenant().tenantId(), source.getId(), target.getId()).orElseGet(PeerMeshAcl::new);
        if (acl.getId() == null) {
            acl.setId(ClientIdGenerator.newId());
            acl.setTenantId(context.tenant().tenantId());
            acl.setCreatedAt(Instant.now().toString());
        }
        acl.setOwnerUsername(context.username());
        acl.setSourceClientId(source.getId());
        acl.setSourceClientName(source.getClientName());
        acl.setTargetClientId(target.getId());
        acl.setTargetClientName(target.getClientName());
        acl.setAllowed(mutation.allowed() == null || mutation.allowed());
        acl.setUpdatedAt(Instant.now().toString());
        return toAclView(aclRepository.save(acl));
    }

    @Transactional
    public void deleteAcl(ManagementContext context, long id) {
        PeerMeshAcl acl = aclRepository.findById(id)
                .filter(row -> row.getTenantId().equals(context.tenant().tenantId()))
                .filter(row -> context.isAdmin() || row.getOwnerUsername().equals(context.username()))
                .orElseThrow(() -> new IllegalArgumentException("peer ACL not found: " + id));
        aclRepository.delete(acl);
    }

    @Transactional(readOnly = true)
    public boolean canPeer(ClientAccount source, ClientAccount target) {
        if (source == null || target == null) {
            return false;
        }
        if (!source.getTenantId().equals(target.getTenantId())) {
            return false;
        }
        if (!isDeviceEnabled(source) || !isDeviceEnabled(target)) {
            return false;
        }
        if (normalizeOwner(source.getOwnerUsername()).equals(normalizeOwner(target.getOwnerUsername()))) {
            return true;
        }
        return aclRepository.findByTenantIdAndSourceClientIdAndTargetClientId(
                        source.getTenantId(), source.getId(), target.getId())
                .map(PeerMeshAcl::isAllowed)
                .orElse(false);
    }

    private boolean isDeviceEnabled(ClientAccount account) {
        return deviceRepository.findByTenantIdAndClientId(account.getTenantId(), account.getId())
                .map(PeerMeshDevice::isEnabled)
                .orElse(false);
    }

    @Transactional(readOnly = true)
    public PeerIdentity peerIdentity(ClientAccount account) {
        if (account == null) {
            return new PeerIdentity("", "");
        }
        return deviceRepository.findByTenantIdAndClientId(account.getTenantId(), account.getId())
                .map(device -> new PeerIdentity(device.getVirtualIp(), device.getPublicKey()))
                .orElseGet(() -> new PeerIdentity("", ""));
    }

    @Transactional
    public PeerSessionGrant createSession(ClientAccount source, ClientAccount target, String pathType) {
        if (!canPeer(source, target)) {
            throw new IllegalArgumentException("peer access denied");
        }
        Instant now = Instant.now();
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
        session.setExpiresAt(now.plusSeconds(properties.getSessionTtlSeconds()).toString());
        return new PeerSessionGrant(toSessionView(sessionRepository.save(session)), token);
    }

    @Transactional
    public PeerMeshSessionView reportPath(ClientAccount reporter, PeerControlMessage report) {
        if (report.getSessionId() == null || report.getSessionId() <= 0) {
            throw new IllegalArgumentException("sessionId is required");
        }
        PeerMeshSession session = findReportableSession(reporter, report.getSessionId());
        Instant now = Instant.now();
        if (closeIfExpired(session, now)) {
            return toSessionView(sessionRepository.save(session));
        }
        if (StringUtils.hasText(report.getPathType())) {
            session.setPathType(limit(report.getPathType(), 40));
        }
        session.setStatus(StringUtils.hasText(report.getStatus())
                ? limit(report.getStatus(), 40)
                : STATUS_ACTIVE);
        session.setRttMillis(report.getRttMillis());
        session.setLocalEndpoint(limit(report.getLocalEndpoint(), 255));
        session.setRemoteEndpoint(limit(report.getRemoteEndpoint(), 255));
        session.setUpdatedAt(now.toString());
        relayAuthorizationCache.remove(session.getId());
        return toSessionView(sessionRepository.save(session));
    }

    @Transactional
    public PeerMeshSessionView reportTraffic(ClientAccount reporter, PeerControlMessage report) {
        if (report.getSessionId() == null || report.getSessionId() <= 0) {
            throw new IllegalArgumentException("sessionId is required");
        }
        PeerMeshSession session = findReportableSession(reporter, report.getSessionId());
        Instant now = Instant.now();
        if (!closeIfExpired(session, now)) {
            applyTraffic(session, Math.max(0, report.getDirectBytes()), Math.max(0, report.getRelayBytes()), now);
        }
        return toSessionView(sessionRepository.save(session));
    }

    @Transactional
    public PeerMeshDeviceView reportDevice(ClientAccount reporter, PeerControlMessage report) {
        PeerMeshDevice device = deviceRepository.findByTenantIdAndClientId(reporter.getTenantId(), reporter.getId())
                .orElseGet(() -> createDevice(reporter));
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
        sessionRepository.findById(sessionId).ifPresent(session -> {
            Instant now = Instant.now();
            if (!closeIfExpired(session, now)) {
                applyTraffic(session, 0, bytes, now);
            }
            sessionRepository.save(session);
        });
    }

    @Transactional
    public boolean authorizeRelayFrame(PeerDataFrameHeader header, long bytes) {
        if (header == null || bytes <= 0) {
            return false;
        }
        return sessionRepository.findById(header.sessionId())
                .map(session -> authorizeRelayFrame(session, header, bytes, Instant.now()))
                .orElse(false);
    }

    public boolean authorizeRelayFrameForRelay(PeerDataFrameHeader header, long bytes) {
        if (header == null || bytes <= 0) {
            return false;
        }
        long nowNanos = System.nanoTime();
        long nowMillis = System.currentTimeMillis();
        RelayAuthorization cached = relayAuthorizationCache.get(header.sessionId());
        if (cached != null && cached.validAt(nowNanos, nowMillis)) {
            if (!cached.matches(header)) {
                return false;
            }
            pendingRelayBytes.computeIfAbsent(header.sessionId(), ignored -> new LongAdder()).add(bytes);
            return true;
        }
        return authorizeRelayFrameForRelaySlow(header, bytes, nowNanos);
    }

    @Transactional
    protected boolean authorizeRelayFrameForRelaySlow(PeerDataFrameHeader header, long bytes, long nowNanos) {
        return sessionRepository.findById(header.sessionId())
                .map(session -> {
                    Instant now = Instant.now();
                    if (closeIfExpired(session, now)) {
                        sessionRepository.save(session);
                        relayAuthorizationCache.remove(header.sessionId());
                        pendingRelayBytes.remove(header.sessionId());
                        return false;
                    }
                    RelayAuthorization authorization = RelayAuthorization.from(session, nowNanos + RELAY_AUTH_CACHE_TTL_NANOS);
                    if (!authorization.active() || !authorization.matches(header)) {
                        relayAuthorizationCache.remove(header.sessionId());
                        return false;
                    }
                    relayAuthorizationCache.put(header.sessionId(), authorization);
                    pendingRelayBytes.computeIfAbsent(header.sessionId(), ignored -> new LongAdder()).add(bytes);
                    return true;
                })
                .orElse(false);
    }

    @Transactional
    public PeerMeshSessionView closeSession(ClientAccount reporter, PeerControlMessage close) {
        if (close.getSessionId() == null || close.getSessionId() <= 0) {
            throw new IllegalArgumentException("sessionId is required");
        }
        PeerMeshSession session = findReportableSession(reporter, close.getSessionId());
        markClosed(session, Instant.now());
        return toSessionView(sessionRepository.save(session));
    }

    @Transactional
    public PeerMeshSessionView closeSession(ManagementContext context, long sessionId) {
        PeerMeshSession session = findAccessibleSession(context, sessionId);
        markClosed(session, Instant.now());
        return toSessionView(sessionRepository.save(session));
    }

    @Transactional
    public List<PeerMeshSessionView> closeOpenSessions(ManagementContext context) {
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
        for (PeerMeshSession session : sessions) {
            markClosed(session, now);
        }
        if (!sessions.isEmpty()) {
            sessionRepository.saveAll(sessions);
        }
        return sessions.stream().map(this::toSessionView).toList();
    }

    @Transactional
    public List<PeerMeshSessionView> closeOpenSessionsForDevice(ManagementContext context, long clientId) {
        PeerMeshDevice device = findAccessibleDevice(context, clientId);
        Instant now = Instant.now();
        List<PeerMeshSession> sessions = sessionRepository.findOpenByClientId(
                context.tenant().tenantId(),
                device.getClientId(),
                STATUS_CLOSED);
        for (PeerMeshSession session : sessions) {
            markClosed(session, now);
        }
        if (!sessions.isEmpty()) {
            sessionRepository.saveAll(sessions);
        }
        return sessions.stream().map(this::toSessionView).toList();
    }

    @Transactional
    public List<PeerMeshSessionView> listSessions(ManagementContext context, int limit) {
        expireStaleSessionsBatch(Instant.now(), 500);
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
        expireStaleSessionsBatch(Instant.now(), 500);
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

    private List<Long> visibleClientIds(ManagementContext context) {
        return clientAccountRepository
                .findByTenantIdAndOwnerUsernameOrderByIdDesc(context.tenant().tenantId(), context.username())
                .stream()
                .map(ClientAccount::getId)
                .toList();
    }

    @Scheduled(fixedDelayString = "${tunnel.peer-mesh.session-cleanup-interval-ms:60000}")
    @Transactional
    public void expireStaleSessions() {
        expireStaleSessionsBatch(Instant.now(), 500);
    }

    @Scheduled(fixedDelayString = "${tunnel.peer-mesh.relay-traffic-flush-interval-ms:5000}")
    @Transactional
    public void flushRelayTraffic() {
        if (pendingRelayBytes.isEmpty()) {
            return;
        }
        Instant now = Instant.now();
        pendingRelayBytes.forEach((sessionId, counter) -> {
            long bytes = counter.sumThenReset();
            if (bytes <= 0) {
                return;
            }
            sessionRepository.findById(sessionId).ifPresentOrElse(session -> {
                if (!closeIfExpired(session, now)) {
                    applyTraffic(session, 0, bytes, now);
                } else {
                    relayAuthorizationCache.remove(sessionId);
                }
                sessionRepository.save(session);
            }, () -> {
                relayAuthorizationCache.remove(sessionId);
                pendingRelayBytes.remove(sessionId);
            });
        });
    }

    @Transactional(readOnly = true)
    public List<PeerRosterItem> allowedRoster(ClientAccount account) {
        if (!properties.isEnabled()) {
            return List.of();
        }
        List<PeerMeshDevice> sameOwner = deviceRepository
                .findByTenantIdAndOwnerUsernameAndEnabledTrueOrderByClientNameAsc(
                        account.getTenantId(), normalizeOwner(account.getOwnerUsername()));
        Map<Long, PeerMeshDevice> devices = sameOwner.stream()
                .collect(Collectors.toMap(PeerMeshDevice::getClientId, item -> item, (left, right) -> left));
        for (PeerMeshAcl acl : aclRepository.findByTenantIdOrderByIdDesc(account.getTenantId())) {
            if (acl.isAllowed() && acl.getSourceClientId().equals(account.getId())) {
                deviceRepository.findByTenantIdAndClientId(account.getTenantId(), acl.getTargetClientId())
                        .filter(PeerMeshDevice::isEnabled)
                        .ifPresent(device -> devices.put(device.getClientId(), device));
            }
        }
        devices.remove(account.getId());
        return devices.values().stream()
                .map(device -> new PeerRosterItem(
                        device.getClientId(),
                        device.getClientName(),
                        device.getVirtualIp(),
                        device.getPublicKey(),
                        SessionUtil.getChannel(device.getClientName()) != null))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ClientAccount> rosterRefreshTargets(ClientAccount account) {
        if (account == null) {
            return List.of();
        }
        return clientAccountRepository.findByTenantIdOrderByIdDesc(account.getTenantId());
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
                session.getPathType(),
                session.getStatus(),
                session.getRttMillis(),
                session.getLocalEndpoint(),
                session.getRemoteEndpoint(),
                session.getDirectBytes(),
                session.getRelayBytes(),
                session.getLastTrafficAt(),
                session.getStartedAt(),
                session.getUpdatedAt(),
                session.getExpiresAt(),
                session.getClosedAt()
        );
    }

    private String resolvePeerHost(String requestServerName) {
        if (StringUtils.hasText(properties.getPublicAddress())) {
            return properties.getPublicAddress().trim();
        }
        return StringUtils.hasText(requestServerName) ? requestServerName.trim() : "";
    }

    private PeerMeshSession findReportableSession(ClientAccount reporter, long sessionId) {
        PeerMeshSession session = sessionRepository.findById(sessionId)
                .filter(row -> row.getTenantId().equals(reporter.getTenantId()))
                .orElseThrow(() -> new IllegalArgumentException("peer session not found: " + sessionId));
        boolean reporterInSession = reporter.getId().equals(session.getSourceClientId())
                || reporter.getId().equals(session.getTargetClientId());
        if (!reporterInSession) {
            throw new IllegalArgumentException("peer session report source mismatch");
        }
        return session;
    }

    private PeerMeshSession findAccessibleSession(ManagementContext context, long sessionId) {
        PeerMeshSession session = sessionRepository.findById(sessionId)
                .filter(row -> row.getTenantId().equals(context.tenant().tenantId()))
                .orElseThrow(() -> new IllegalArgumentException("peer session not found: " + sessionId));
        if (context.isAdmin() || ownsClient(context, session.getSourceClientId()) || ownsClient(context, session.getTargetClientId())) {
            return session;
        }
        throw new IllegalArgumentException("peer session not found: " + sessionId);
    }

    private boolean ownsClient(ManagementContext context, Long clientId) {
        if (clientId == null) {
            return false;
        }
        return clientAccountRepository
                .findByIdAndTenantIdAndOwnerUsername(clientId, context.tenant().tenantId(), context.username())
                .isPresent();
    }

    private void applyTraffic(PeerMeshSession session, long directBytes, long relayBytes, Instant now) {
        if (directBytes <= 0 && relayBytes <= 0) {
            return;
        }
        session.setDirectBytes(saturatedAdd(session.getDirectBytes(), directBytes));
        session.setRelayBytes(saturatedAdd(session.getRelayBytes(), relayBytes));
        session.setLastTrafficAt(now.toString());
        session.setUpdatedAt(now.toString());
    }

    private boolean authorizeRelayFrame(PeerMeshSession session, PeerDataFrameHeader header, long bytes, Instant now) {
        if (closeIfExpired(session, now)) {
            sessionRepository.save(session);
            return false;
        }
        if (!STATUS_ACTIVE.equals(session.getStatus())) {
            return false;
        }
        boolean forward = header.fromClientId() == session.getSourceClientId()
                && header.toClientId() == session.getTargetClientId();
        boolean reverse = header.fromClientId() == session.getTargetClientId()
                && header.toClientId() == session.getSourceClientId();
        if (!forward && !reverse) {
            return false;
        }
        applyTraffic(session, 0, bytes, now);
        sessionRepository.save(session);
        return true;
    }

    private int expireStaleSessionsBatch(Instant now, int limit) {
        List<PeerMeshSession> expired = sessionRepository
                .findByStatusNotAndExpiresAtLessThanEqualOrderByExpiresAtAsc(
                        STATUS_CLOSED,
                        now.toString(),
                        PageRequest.of(0, Math.clamp(limit, 1, 1000)));
        for (PeerMeshSession session : expired) {
            markClosed(session, now);
        }
        if (!expired.isEmpty()) {
            sessionRepository.saveAll(expired);
        }
        return expired.size();
    }

    private boolean closeIfExpired(PeerMeshSession session, Instant now) {
        if (STATUS_CLOSED.equals(session.getStatus())) {
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
        if (!STATUS_CLOSED.equals(session.getStatus())) {
            session.setStatus(STATUS_CLOSED);
        }
        if (!StringUtils.hasText(session.getClosedAt())) {
            session.setClosedAt(now.toString());
        }
        session.setUpdatedAt(now.toString());
        if (session.getId() != null) {
            relayAuthorizationCache.remove(session.getId());
            pendingRelayBytes.remove(session.getId());
        }
    }

    private long saturatedAdd(long current, long delta) {
        if (delta <= 0) {
            return current;
        }
        long next = current + delta;
        return next < 0 ? Long.MAX_VALUE : next;
    }

    private String serverPublicKey() {
        return HexFormat.of().formatHex(HmacSigner.sha256("shuai-tunnel-peer-mesh-server"));
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

    public record AclMutation(Long sourceClientId, Long targetClientId, Boolean allowed) {
    }

    public record PeerRosterItem(long clientId, String clientName, String virtualIp, String publicKey, boolean online) {
    }

    public record PeerSessionGrant(PeerMeshSessionView session, String token) {
    }

    public record PeerIdentity(String virtualIp, String publicKey) {
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

        private boolean matches(PeerDataFrameHeader header) {
            boolean forward = header.fromClientId() == sourceClientId && header.toClientId() == targetClientId;
            boolean reverse = header.fromClientId() == targetClientId && header.toClientId() == sourceClientId;
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
}
