package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ClientSession;
import com.theshuai.specusserver.management.model.PeerMeshSessionView;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
@Slf4j
public class PeerSignalService {
    private final ClientAccountService clientAccountService;
    private final PeerMeshService peerMeshService;
    private final PeerServiceDiscoveryService peerServiceDiscoveryService;
    private final ClientSessionRepository clientSessionRepository;
    private final PeerEgressService peerEgressService;

    public PeerSignalService(ClientAccountService clientAccountService,
                             PeerMeshService peerMeshService,
                             PeerServiceDiscoveryService peerServiceDiscoveryService,
                             ClientSessionRepository clientSessionRepository,
                             PeerEgressService peerEgressService) {
        this.clientAccountService = clientAccountService;
        this.peerMeshService = peerMeshService;
        this.peerServiceDiscoveryService = peerServiceDiscoveryService;
        this.clientSessionRepository = clientSessionRepository;
        this.peerEgressService = peerEgressService;
    }

    @Transactional
    public void handle(MessageRequestPacket request, Session session) {
        if (!peerMeshService.isEnabled()) {
            throw new IllegalStateException("peer mesh is disabled");
        }
        if (session == null || !StringUtils.hasText(session.getClientName())) {
            throw new IllegalArgumentException("peer signal requires authenticated client");
        }
        ClientAccount source = clientAccountService.findClientByName(session.getClientName())
                .orElseThrow(() -> new IllegalArgumentException("source client not found: " + session.getClientName()));
        PeerControlMessage signal = parseSignal(request.getMessage());
        if (PeerControlMessage.TYPE_SERVICE_REPORT.equals(signal.getType())) {
            validateServiceReportEnvelope(request);
            pushCatalogs(peerServiceDiscoveryService.handleReport(source, signal));
            return;
        }
        if (PeerControlMessage.TYPE_EGRESS_REPORT.equals(signal.getType())) {
            PeerEgressService.validateReportEnvelope(request.getMessage(), request.getToClientName());
            peerEgressService.handleReport(source, signal, authenticatedEgressSessionId(source));
            return;
        }
        fillSource(signal, source);

        if (PeerControlMessage.TYPE_PATH_REPORT.equals(signal.getType())) {
            peerMeshService.reportPath(source, signal);
            return;
        }
        if (PeerControlMessage.TYPE_TRAFFIC_REPORT.equals(signal.getType())) {
            peerMeshService.reportTraffic(source, signal);
            return;
        }
        if (PeerControlMessage.TYPE_DEVICE_REPORT.equals(signal.getType())) {
            peerMeshService.reportDevice(source, signal);
            return;
        }
        if (PeerControlMessage.TYPE_CLOSE.equals(signal.getType())) {
            peerMeshService.closeSession(source, signal);
            if (!StringUtils.hasText(request.getToClientName())) {
                return;
            }
        }
        if (PeerControlMessage.TYPE_SERVICE_CATALOG.equals(signal.getType())) {
            throw new IllegalArgumentException("service-catalog is server-only");
        }
        if (PeerControlMessage.TYPE_EGRESS_CONFIG.equals(signal.getType())
                || PeerControlMessage.TYPE_EGRESS_CATALOG.equals(signal.getType())) {
            throw new IllegalArgumentException(signal.getType() + " is server-only");
        }

        if (!StringUtils.hasText(request.getToClientName())) {
            throw new IllegalArgumentException("toClientName is required");
        }
        ClientAccount target = clientAccountService.findClientByName(request.getToClientName().trim())
                .orElseThrow(() -> new IllegalArgumentException("target client not found: " + request.getToClientName()));
        if (!peerMeshService.canPeer(source, target)) {
            throw new IllegalArgumentException("peer access denied");
        }

        Channel targetChannel = SessionUtil.getChannel(target.getClientName());
        if (targetChannel == null || !SessionUtil.hasLogin(targetChannel)) {
            throw new IllegalStateException("target peer is offline: " + target.getClientName());
        }

        enrichTarget(signal, target);
        if (shouldOpenSession(signal)) {
            PeerMeshService.PeerSessionGrant grant = peerMeshService.createSession(source, target, PeerMeshService.PATH_DIRECT);
            signal.setSessionId(grant.session().id());
            signal.setToken(grant.token());
            signal.setExpiresAt(grant.session().expiresAt());
            sendSessionGrant(source, target, grant);
        }
        sendSignal(targetChannel, source.getClientName(), target.getClientName(), signal);
    }

    static void validateServiceReportEnvelope(MessageRequestPacket request) {
        if (request.getMessage().getBytes(StandardCharsets.UTF_8).length
                > PeerServiceDiscovery.MAX_SNAPSHOT_BYTES) {
            throw new IllegalArgumentException("service-report exceeds 16384 bytes");
        }
        if (StringUtils.hasText(request.getToClientName())) {
            throw new IllegalArgumentException("service-report toClientName must be empty");
        }
        JsonNode root = JsonUtil.readString(request.getMessage());
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("invalid service-report");
        }
        for (String field : List.of(
                "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
                "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
                "sessionId", "token", "publisherClientId", "publisherClientName", "publisherSessionId")) {
            if (root.has(field)) {
                throw new IllegalArgumentException("service-report " + field + " is server-bound");
            }
        }
    }

    public void pushRoster(ClientAccount account) {
        if (!peerMeshService.isEnabled()) {
            return;
        }
        Channel channel = SessionUtil.getChannel(account.getClientName());
        if (channel == null || !SessionUtil.hasLogin(channel)) {
            return;
        }
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("type", PeerControlMessage.TYPE_ROSTER);
        message.put("clientId", account.getId());
        message.put("clientName", account.getClientName());
        message.put("peers", peerMeshService.allowedRoster(account));

        MessageResponsePacket packet = new MessageResponsePacket();
        packet.setClientName("server");
        packet.setToClientName(account.getClientName());
        packet.setMessageType(MessageType.PEER_CONTROL);
        packet.setMessage(JsonUtil.objectToString(message));
        channel.writeAndFlush(packet);
    }

    public void pushOnLogin(ClientAccount account) {
        if (!peerMeshService.isEnabled() || account == null) {
            return;
        }
        pushConfig(account);
        pushCatalogs(peerServiceDiscoveryService.catalogsForRecipient(account));
        pushEgress(account);
        for (ClientAccount target : peerMeshService.rosterRefreshTargets(account)) {
            pushRoster(target);
            pushEgress(target);
        }
    }

    public List<PeerMeshSessionView> refreshDevice(ManagementContext context, long clientId, boolean enabled) {
        ClientAccount account = clientAccountService.findClientById(context, clientId);
        pushConfig(account);

        List<PeerMeshSessionView> closedSessions = enabled
                ? List.of()
                : peerMeshService.closeOpenSessionsForDevice(context, clientId);
        for (PeerMeshSessionView closed : closedSessions) {
            sendClose(closed);
        }

        for (ClientAccount target : peerMeshService.rosterRefreshTargets(account)) {
            pushRoster(target);
        }
        List<PeerServiceDiscoveryService.CatalogDelivery> catalogs = new java.util.ArrayList<>();
        if (enabled) {
            catalogs.addAll(peerServiceDiscoveryService.onAuthorizationChanged(account.getTenantId()));
        } else {
            catalogs.addAll(peerServiceDiscoveryService.withdrawClient(
                    account.getTenantId(), account.getId(), "device-disabled"));
            catalogs.addAll(peerServiceDiscoveryService.onAuthorizationChanged(account.getTenantId()));
        }
        pushCatalogs(catalogs);
        return closedSessions;
    }

    public void onClientDisconnected(Long sessionId) {
        if (sessionId == null || sessionId <= 0) {
            return;
        }
        ClientSession session = clientSessionRepository.findById(sessionId).orElse(null);
        if (session == null || !StringUtils.hasText(session.getClientName())) {
            return;
        }
        clientAccountService.findClientByName(session.getClientName()).ifPresent(account ->
                pushCatalogs(peerServiceDiscoveryService.onClientDisconnected(account, sessionId)));
    }

    public void pushSharingConfig(ManagementContext context) {
        for (ClientAccount account : clientAccountService.listTenantAccounts(context.tenant())) {
            pushConfig(account);
        }
    }

    public void pushServiceConfig(ManagementContext context, long clientId) {
        clientAccountService.listTenantAccounts(context.tenant()).stream()
                .filter(account -> account.getId() == clientId)
                .findFirst()
                .ifPresent(this::pushConfig);
    }

    public void refreshAuthorization(ManagementContext context) {
        for (ClientAccount account : clientAccountService.listTenantAccounts(context.tenant())) {
            pushConfig(account);
            pushRoster(account);
        }
        for (PeerMeshSessionView closed : peerMeshService.closeUnauthorizedSessions(context)) {
            sendClose(closed);
        }
        pushCatalogs(peerServiceDiscoveryService.onAuthorizationChanged(context.tenant().tenantId()));
    }

    public void pushCatalogs(List<PeerServiceDiscoveryService.CatalogDelivery> deliveries) {
        if (deliveries == null || deliveries.isEmpty()) {
            return;
        }
        for (PeerServiceDiscoveryService.CatalogDelivery delivery : deliveries) {
            Channel channel = SessionUtil.getChannel(delivery.recipient().getClientName());
            if (channel == null || !SessionUtil.hasLogin(channel)) {
                continue;
            }
            sendSignal(channel, "server", delivery.recipient().getClientName(), delivery.catalog());
        }
    }

    @Scheduled(fixedDelay = 30_000)
    public void expirePeerServiceCatalogs() {
        pushCatalogs(peerServiceDiscoveryService.expireStale());
    }

    /**
     * Sends the current {@code egress-config} and {@code egress-catalog} to one device.
     *
     * <p>A client that announced no egress capability at login gets nothing, so a runtime that would
     * not understand the payload never receives it.
     */
    public void pushEgress(ClientAccount account) {
        if (!peerMeshService.isEnabled() || account == null) {
            return;
        }
        Channel channel = SessionUtil.getChannel(account.getClientName());
        if (channel == null || !SessionUtil.hasLogin(channel)) {
            return;
        }
        int version = clientEgressVersion(account);
        if (version < 1) {
            return;
        }
        PeerControlMessage config = peerEgressService.buildEgressConfig(account, version);
        if (config != null) {
            config.setSourceClientId(account.getId());
            config.setSourceClientName(account.getClientName());
            config.setTargetClientId(account.getId());
            config.setTargetClientName(account.getClientName());
            config.setCreatedAtMillis(System.currentTimeMillis());
            sendSignal(channel, "server", account.getClientName(), config);
        }
        PeerControlMessage catalog = peerEgressService.buildEgressCatalog(account, version);
        if (catalog != null) {
            catalog.setSourceClientId(account.getId());
            catalog.setSourceClientName(account.getClientName());
            catalog.setTargetClientId(account.getId());
            catalog.setTargetClientName(account.getClientName());
            catalog.setCreatedAtMillis(System.currentTimeMillis());
            sendSignal(channel, "server", account.getClientName(), catalog);
        }
    }

    /**
     * Refreshes every online device in the tenant after a policy change.
     *
     * <p>A policy change moves two things at once: what the egress node itself will accept, and
     * which egresses its peers can see. Both sides are refreshed together so the catalogue never
     * advertises an egress that has already stopped accepting the viewer.
     */
    public void pushTenantEgress(String tenantId) {
        if (!StringUtils.hasText(tenantId)) {
            return;
        }
        for (ClientAccount account : clientAccountService.listTenantAccounts(tenantId)) {
            pushEgress(account);
        }
    }

    /**
     * Binds the reporter to its authenticated control connection.
     *
     * <p>The session comes from the channel, is re-checked against the account and tenant, and must
     * be the one currently online. Nothing here is read from the report body.
     */
    private long authenticatedEgressSessionId(ClientAccount source) {
        Channel channel = SessionUtil.getChannel(source.getClientName());
        if (channel == null) {
            throw new IllegalArgumentException("egress session is required");
        }
        Long sessionId = channel.attr(ServerAttributes.CLIENT_SESSION_ID).get();
        if (sessionId == null || sessionId <= 0) {
            throw new IllegalArgumentException("egress session is required");
        }
        ClientSession session = clientSessionRepository.findById(sessionId)
                .filter(row -> row.getClientId() == source.getId())
                .filter(row -> Objects.equals(row.getTenantId(), source.getTenantId()))
                .filter(row -> ClientAuthService.STATUS_NETTY_ONLINE.equals(row.getStatus()))
                .orElseThrow(() -> new IllegalArgumentException("egress session is not current"));
        if (session.getClientEgressVersion() < 1) {
            throw new IllegalArgumentException("client did not announce egress capability");
        }
        return sessionId;
    }

    private int clientEgressVersion(ClientAccount account) {
        return clientSessionRepository
                .findByTenantIdAndClientIdInAndStatus(account.getTenantId(), List.of(account.getId()),
                        ClientAuthService.STATUS_NETTY_ONLINE)
                .stream()
                .mapToInt(ClientSession::getClientEgressVersion)
                .max()
                .orElse(0);
    }

    /** Whether a client currently holds a logged-in control channel. */
    public boolean isOnline(String clientName) {
        Channel channel = SessionUtil.getChannel(clientName);
        return channel != null && SessionUtil.hasLogin(channel);
    }

    public void pushConfig(ClientAccount account) {
        Channel channel = SessionUtil.getChannel(account.getClientName());
        if (channel == null || !SessionUtil.hasLogin(channel)) {
            return;
        }
        PeerControlMessage config = new PeerControlMessage();
        config.setType(PeerControlMessage.TYPE_CONFIG);
        config.setSourceClientId(account.getId());
        config.setSourceClientName(account.getClientName());
        config.setTargetClientId(account.getId());
        config.setTargetClientName(account.getClientName());
        var peerMeshConfig = peerMeshService.buildRuntimeConfig(account);
        config.setPeerMesh(peerMeshConfig);
        config.setCreatedAtMillis(System.currentTimeMillis());
        log.info("[peer-mesh] push runtime config: client={}, enabled={}, virtualIp={}",
                account.getClientName(), peerMeshConfig.isEnabled(), peerMeshConfig.getVirtualIp());
        sendSignal(channel, "server", account.getClientName(), config);
    }

    public PeerMeshSessionView forceClose(ManagementContext context, long sessionId) {
        PeerMeshSessionView closed = peerMeshService.closeSession(context, sessionId);
        sendClose(closed);
        return closed;
    }

    public List<PeerMeshSessionView> forceCloseOpenSessions(ManagementContext context) {
        List<PeerMeshSessionView> closedSessions = peerMeshService.closeOpenSessions(context);
        for (PeerMeshSessionView closed : closedSessions) {
            sendClose(closed);
        }
        return closedSessions;
    }

    private void sendClose(PeerMeshSessionView closed) {
        PeerControlMessage close = new PeerControlMessage();
        close.setType(PeerControlMessage.TYPE_CLOSE);
        close.setSessionId(closed.id());
        close.setSourceClientId(closed.sourceClientId());
        close.setSourceClientName(closed.sourceClientName());
        close.setTargetClientId(closed.targetClientId());
        close.setTargetClientName(closed.targetClientName());
        close.setStatus(closed.status());
        close.setReason("admin-force-close");
        close.setCreatedAtMillis(System.currentTimeMillis());
        sendCloseIfOnline(closed.sourceClientName(), close);
        sendCloseIfOnline(closed.targetClientName(), close);
    }

    private PeerControlMessage parseSignal(String raw) {
        PeerControlMessage signal = JsonUtil.stringToObject(raw, PeerControlMessage.class);
        if (signal == null || !StringUtils.hasText(signal.getType())) {
            throw new IllegalArgumentException("invalid peer signal");
        }
        return signal;
    }

    private void fillSource(PeerControlMessage signal, ClientAccount source) {
        signal.setSourceClientId(source.getId());
        signal.setSourceClientName(source.getClientName());
        PeerMeshService.PeerIdentity identity = peerMeshService.peerIdentity(source);
        signal.setSourceVirtualIp(identity.virtualIp());
        signal.setSourcePublicKey(identity.publicKey());
        if (signal.getCreatedAtMillis() <= 0) {
            signal.setCreatedAtMillis(System.currentTimeMillis());
        }
    }

    private void enrichTarget(PeerControlMessage signal, ClientAccount target) {
        signal.setTargetClientId(target.getId());
        signal.setTargetClientName(target.getClientName());
        PeerMeshService.PeerIdentity identity = peerMeshService.peerIdentity(target);
        signal.setTargetVirtualIp(identity.virtualIp());
        signal.setTargetPublicKey(identity.publicKey());
    }

    private boolean shouldOpenSession(PeerControlMessage signal) {
        return signal.getSessionId() == null
                && (PeerControlMessage.TYPE_CANDIDATES.equals(signal.getType())
                || "offer".equals(signal.getType()));
    }

    private void sendSessionGrant(ClientAccount source, ClientAccount target, PeerMeshService.PeerSessionGrant grant) {
        Channel sourceChannel = SessionUtil.getChannel(source.getClientName());
        if (sourceChannel == null || !SessionUtil.hasLogin(sourceChannel)) {
            return;
        }
        PeerControlMessage grantMessage = new PeerControlMessage();
        grantMessage.setType(PeerControlMessage.TYPE_SESSION_GRANT);
        grantMessage.setSessionId(grant.session().id());
        grantMessage.setSourceClientId(source.getId());
        grantMessage.setSourceClientName(source.getClientName());
        grantMessage.setTargetClientId(target.getId());
        grantMessage.setTargetClientName(target.getClientName());
        PeerMeshService.PeerIdentity sourceIdentity = peerMeshService.peerIdentity(source);
        PeerMeshService.PeerIdentity targetIdentity = peerMeshService.peerIdentity(target);
        grantMessage.setSourceVirtualIp(sourceIdentity.virtualIp());
        grantMessage.setSourcePublicKey(sourceIdentity.publicKey());
        grantMessage.setTargetVirtualIp(targetIdentity.virtualIp());
        grantMessage.setTargetPublicKey(targetIdentity.publicKey());
        grantMessage.setToken(grant.token());
        grantMessage.setExpiresAt(grant.session().expiresAt());
        grantMessage.setPathType(grant.session().pathType());
        grantMessage.setStatus(grant.session().status());
        grantMessage.setCreatedAtMillis(System.currentTimeMillis());
        sendSignal(sourceChannel, "server", source.getClientName(), grantMessage);
    }

    private void sendSignal(Channel channel, String sourceClientName, String targetClientName, PeerControlMessage signal) {
        MessageResponsePacket response = new MessageResponsePacket();
        response.setMessageType(MessageType.PEER_CONTROL);
        response.setClientName(sourceClientName);
        response.setToClientName(targetClientName);
        response.setMessage(JsonUtil.objectToString(signal));
        channel.writeAndFlush(response).addListener(future -> {
            if (!future.isSuccess()) {
                log.warn("[peer-mesh] signal write failed source={} target={}",
                        sourceClientName, targetClientName, future.cause());
            }
        });
    }

    private void sendCloseIfOnline(String clientName, PeerControlMessage signal) {
        if (!StringUtils.hasText(clientName)) {
            return;
        }
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel == null || !SessionUtil.hasLogin(channel)) {
            return;
        }
        sendSignal(channel, "server", clientName, signal);
    }
}
