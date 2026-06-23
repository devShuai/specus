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
import java.util.stream.Collectors;

@Service
public class PeerMeshService {
    public static final String PATH_DIRECT = "DIRECT";
    public static final String PATH_RELAY = "RELAY";
    public static final String STATUS_NEGOTIATING = "NEGOTIATING";
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_CLOSED = "CLOSED";

    private final PeerMeshProperties properties;
    private final PeerMeshDeviceRepository deviceRepository;
    private final PeerMeshAclRepository aclRepository;
    private final PeerMeshSessionRepository sessionRepository;
    private final ClientAccountRepository clientAccountRepository;

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
        ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
        config.setEnabled(false);
        config.setClientId(account.getId());
        config.setClientName(account.getClientName());
        config.setCidr(properties.getCidr());
        config.setSessionTtlSeconds(properties.getSessionTtlSeconds());
        if (!properties.isEnabled()) {
            return config;
        }

        PeerMeshDevice device = ensureDevice(account, environment);
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
        if (normalizeOwner(source.getOwnerUsername()).equals(normalizeOwner(target.getOwnerUsername()))) {
            return true;
        }
        return aclRepository.findByTenantIdAndSourceClientIdAndTargetClientId(
                        source.getTenantId(), source.getId(), target.getId())
                .map(PeerMeshAcl::isAllowed)
                .orElse(false);
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
    public List<PeerMeshSessionView> listSessions(ManagementContext context, int limit) {
        expireStaleSessionsBatch(Instant.now(), 500);
        int pageSize = Math.clamp(limit, 1, 200);
        List<PeerMeshSession> sessions;
        if (context.isAdmin()) {
            sessions = sessionRepository.findByTenantIdOrderByUpdatedAtDesc(
                    context.tenant().tenantId(), PageRequest.of(0, pageSize));
        } else {
            List<Long> visible = clientAccountRepository
                    .findByTenantIdAndOwnerUsernameOrderByIdDesc(context.tenant().tenantId(), context.username())
                    .stream()
                    .map(ClientAccount::getId)
                    .toList();
            if (visible.isEmpty()) {
                return List.of();
            }
            sessions = sessionRepository.findVisible(
                    context.tenant().tenantId(), visible, PageRequest.of(0, pageSize));
        }
        return sessions.stream().map(this::toSessionView).toList();
    }

    @Scheduled(fixedDelayString = "${tunnel.peer-mesh.session-cleanup-interval-ms:60000}")
    @Transactional
    public void expireStaleSessions() {
        expireStaleSessionsBatch(Instant.now(), 500);
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

    public record AclMutation(Long sourceClientId, Long targetClientId, Boolean allowed) {
    }

    public record PeerRosterItem(long clientId, String clientName, String virtualIp, String publicKey, boolean online) {
    }

    public record PeerSessionGrant(PeerMeshSessionView session, String token) {
    }
}
