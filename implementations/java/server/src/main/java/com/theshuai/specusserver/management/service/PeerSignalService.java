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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class PeerSignalService {
    private final ClientAccountService clientAccountService;
    private final PeerMeshService peerMeshService;
    private final PeerServiceDiscoveryService peerServiceDiscoveryService;
    private final ClientSessionRepository clientSessionRepository;
    private final PeerEgressService peerEgressService;
    private final ConcurrentLinkedQueue<ClientPeerReferences.Deleted> deletedClients = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<PendingNegotiation> pendingSignals = new ConcurrentLinkedQueue<>();
    private final Semaphore signalSlots;
    private final Semaphore signalBytes = new Semaphore(16 * 1024 * 1024);
    private final Map<String,ManagementContext> committedAuthorizationRefreshes = new ConcurrentHashMap<>();
    private static final int MAX_SIGNAL_BYTES = 64 * 1024;
    private static final long SIGNAL_TTL_NANOS = TimeUnit.SECONDS.toNanos(10);

    private static boolean transactionActive() {
        return TransactionSynchronizationManager.isSynchronizationActive() && TransactionSynchronizationManager.isActualTransactionActive();
    }
    private static void afterCommit(Runnable effect) {
        Runnable committed = () -> PeerCatalogCache.committedEffect(() -> {
            PeerCatalogCache.flushCommittedEffects();
            effect.run();
        });
        if (transactionActive() && !PeerCatalogCache.inCommittedEffect()) TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() { committed.run(); }
        }); else committed.run();
    }
    private static ClientAccount reference(ClientAccount account) {
        ClientAccount result = new ClientAccount(); result.setId(account.getId()); result.setTenantId(account.getTenantId()); result.setClientName(account.getClientName()); return result;
    }
    private record ChannelBinding(Channel channel, Session session, Long authenticatedSession, String tenant) {
        private ChannelBinding(Channel channel) { this(channel,SessionUtil.getSession(channel),channel.attr(ServerAttributes.CLIENT_SESSION_ID).get(),channel.attr(ServerAttributes.TENANT_ID).get()); }
        private boolean matches(String clientName) {
            return channel.isActive() && session != null && clientName.equals(session.getClientName())
                    && SessionUtil.getChannel(clientName) == channel && SessionUtil.getSession(channel) == session
                    && Objects.equals(authenticatedSession,channel.attr(ServerAttributes.CLIENT_SESSION_ID).get())
                    && Objects.equals(tenant,channel.attr(ServerAttributes.TENANT_ID).get());
        }
    }
    private final class SignalReservation {
        private int bytes; private final AtomicBoolean released = new AtomicBoolean();
        private void release() { if (released.compareAndSet(false,true)) { signalSlots.release(); if (bytes > 0) signalBytes.release(bytes); } }
    }
    private final class PendingNegotiation {
        private final ClientAccount source,target;
        private final ChannelBinding sourceBinding,targetBinding;
        private final String encoded;
        private final boolean sendGrant;
        private final SignalReservation reservation;
        private final long created = System.nanoTime();
        private int attempts;
        private PendingNegotiation(ClientAccount source,ClientAccount target,ChannelBinding sourceBinding,ChannelBinding targetBinding,
                                   String encoded,boolean sendGrant,SignalReservation reservation) {
            this.source=source; this.target=target; this.sourceBinding=sourceBinding; this.targetBinding=targetBinding;
            this.encoded=encoded; this.sendGrant=sendGrant; this.reservation=reservation;
        }
    }

    /** Ephemeral negotiation, not the durable ownership-change outbox. Enqueue only after commit;
     * drain on another execution so SQLite pool1's producer connection has been released. */
    @Scheduled(fixedDelayString = "${specus.peer-mesh.signal-publish-interval-ms:25}")
    public void publishPendingSignals() {
        for (int i=0;i<64;i++) {
            PendingNegotiation pending = pendingSignals.poll(); if (pending == null) return;
            boolean retry = false;
            try {
                if (System.nanoTime()-pending.created > SIGNAL_TTL_NANOS || !pending.sourceBinding.matches(pending.source.getClientName())
                        || !pending.targetBinding.matches(pending.target.getClientName())) continue;
                PeerControlMessage signal = parseSignal(pending.encoded);
                peerMeshService.publishAuthorizedSignal(pending.source,pending.target,signal.getSessionId(),signal.getToken(),current -> {
                    if (!pending.source.getClientName().equals(current.source().account().getClientName())
                            || !pending.target.getClientName().equals(current.target().account().getClientName())) return;
                    bindSignal(signal,current);
                    signal.setToken(current.grant().token()); signal.setExpiresAt(current.grant().session().expiresAt());
                    if (pending.sendGrant) writeEncoded(pending.sourceBinding,"server",pending.source.getClientName(),
                            JsonUtil.objectToString(grantMessage(current)));
                    writeEncoded(pending.targetBinding,pending.source.getClientName(),pending.target.getClientName(),JsonUtil.objectToString(signal));
                });
            } catch (IllegalArgumentException denied) {
                log.debug("[peer-mesh] committed signal no longer authorized source={} target={}",pending.source.getId(),pending.target.getId());
            } catch (RuntimeException failure) {
                retry = ++pending.attempts < 3 && System.nanoTime()-pending.created <= SIGNAL_TTL_NANOS;
                log.warn("[peer-mesh] committed signal publication failed source={} target={} retry={}",pending.source.getId(),pending.target.getId(),retry);
                if (retry) pendingSignals.add(pending);
            } finally { if (!retry) pending.reservation.release(); }
            if (retry) return;
        }
    }

    private static void bindSignal(PeerControlMessage signal,PeerMeshService.AuthorizedSignal current) {
        signal.setSourceClientId(current.source().account().getId()); signal.setSourceClientName(current.source().account().getClientName());
        signal.setSourceVirtualIp(current.source().identity().virtualIp()); signal.setSourcePublicKey(current.source().identity().publicKey());
        signal.setTargetClientId(current.target().account().getId()); signal.setTargetClientName(current.target().account().getClientName());
        signal.setTargetVirtualIp(current.target().identity().virtualIp()); signal.setTargetPublicKey(current.target().identity().publicKey());
        signal.setCreatedAtMillis(System.currentTimeMillis());
    }
    private static PeerControlMessage grantMessage(PeerMeshService.AuthorizedSignal current) {
        PeerControlMessage result = new PeerControlMessage(); result.setType(PeerControlMessage.TYPE_SESSION_GRANT); bindSignal(result,current);
        var grant = current.grant(); result.setSessionId(grant.session().id()); result.setToken(grant.token()); result.setExpiresAt(grant.session().expiresAt());
        result.setPathType(grant.session().pathType()); result.setStatus(grant.session().status()); return result;
    }

    public PeerSignalService(ClientAccountService clientAccountService,
                             PeerMeshService peerMeshService,
                             PeerServiceDiscoveryService peerServiceDiscoveryService,
                             ClientSessionRepository clientSessionRepository,
                             PeerEgressService peerEgressService) {
        this(clientAccountService,peerMeshService,peerServiceDiscoveryService,clientSessionRepository,peerEgressService,1024);
    }

    @Autowired
    public PeerSignalService(ClientAccountService clientAccountService, PeerMeshService peerMeshService,
                             PeerServiceDiscoveryService peerServiceDiscoveryService, ClientSessionRepository clientSessionRepository,
                             PeerEgressService peerEgressService, @Value("${specus.peer-mesh.signal-queue-capacity:1024}") int capacity) {
        if (capacity < 1 || capacity > 65536) throw new IllegalArgumentException("invalid peer signal queue capacity");
        signalSlots = new Semaphore(capacity);
        this.clientAccountService = clientAccountService;
        this.peerMeshService = peerMeshService;
        this.peerServiceDiscoveryService = peerServiceDiscoveryService;
        this.clientSessionRepository = clientSessionRepository;
        this.peerEgressService = peerEgressService;
    }

    @Transactional
    public void handle(MessageRequestPacket request, Session session) {
        handle(request,session,session == null ? null : SessionUtil.getChannel(session.getClientName()));
    }

    @Transactional
    public void handle(MessageRequestPacket request, Session session, Channel incoming) {
        if (!peerMeshService.isEnabled()) {
            throw new IllegalStateException("peer mesh is disabled");
        }
        if (session == null || !StringUtils.hasText(session.getClientName())) {
            throw new IllegalArgumentException("peer signal requires authenticated client");
        }
        if (incoming == null || SessionUtil.getChannel(session.getClientName()) != incoming
                || SessionUtil.getSession(incoming) != session || !incoming.isActive()
                || !session.getClientName().equals(SessionUtil.getSession(incoming).getClientName()))
            throw new IllegalArgumentException("peer control connection is no longer current");
        ClientAccount source = clientAccountService.findClientByName(session.getClientName())
                .orElseThrow(() -> new IllegalArgumentException("source client not found: " + session.getClientName()));
        PeerControlMessage signal = parseSignal(request.getMessage());
        String tenant = incoming.attr(ServerAttributes.TENANT_ID).get();
        if (tenant != null && !tenant.equals(source.getTenantId())) throw new IllegalArgumentException("peer control tenant mismatch");
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
            var closed = peerMeshService.closeSignalSession(source,signal);
            PeerControlMessage close = closeMessage(closed.session(),"peer-requested-close");
            if (closed.source() != null) close.setSourceClientName(closed.source().getClientName());
            if (closed.target() != null) close.setTargetClientName(closed.target().getClientName());
            if (closed.source() != null) sendCloseIfOnline(closed.source().getClientName(),close);
            if (closed.target() != null) sendCloseIfOnline(closed.target().getClientName(),close);
            return;
        }
        if (!List.of("offer","answer",PeerControlMessage.TYPE_CANDIDATES).contains(signal.getType()))
            throw new IllegalArgumentException("unsupported client peer signal type");
        if (request.getMessage().getBytes(StandardCharsets.UTF_8).length > MAX_SIGNAL_BYTES)
            throw new IllegalArgumentException("peer signal is too large");

        if (!StringUtils.hasText(request.getToClientName())) {
            throw new IllegalArgumentException("toClientName is required");
        }
        ClientAccount target = clientAccountService.findClientByName(request.getToClientName().trim())
                .orElseThrow(() -> new IllegalArgumentException("target client not found: " + request.getToClientName()));
        Channel targetChannel = SessionUtil.getChannel(target.getClientName());
        if (targetChannel == null || !SessionUtil.hasLogin(targetChannel)) {
            throw new IllegalStateException("target peer is offline: " + target.getClientName());
        }
        String targetTenant = targetChannel.attr(ServerAttributes.TENANT_ID).get();
        if (targetTenant != null && !targetTenant.equals(source.getTenantId())) throw new IllegalArgumentException("peer target tenant mismatch");

        if (!signalSlots.tryAcquire()) throw new IllegalStateException("peer signal queue is busy");
        SignalReservation reservation = new SignalReservation(); boolean submitted = false;
        try {
            var current = peerMeshService.authorizeSignal(source,target,signal.getSessionId(),signal.getToken());
            boolean sendGrant = shouldOpenSession(signal);
            var grant = sendGrant ? peerMeshService.createSession(current.source().account(),current.target().account(),PeerMeshService.PATH_DIRECT) : current.grant();
            if (grant == null) throw new IllegalArgumentException("sessionId is required");
            signal.setSessionId(grant.session().id()); signal.setToken(grant.token()); signal.setExpiresAt(grant.session().expiresAt());
            bindSignal(signal,current);
            String encoded = JsonUtil.objectToString(signal);
            int bytes = encoded.getBytes(StandardCharsets.UTF_8).length;
            if (bytes > MAX_SIGNAL_BYTES || !signalBytes.tryAcquire(bytes + 2048)) throw new IllegalStateException("peer signal byte budget exceeded");
            reservation.bytes = bytes + 2048;
            PendingNegotiation pending = new PendingNegotiation(reference(current.source().account()),reference(current.target().account()),
                    new ChannelBinding(incoming),new ChannelBinding(targetChannel),encoded,sendGrant,reservation);
            if (transactionActive()) TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCommit() { pendingSignals.add(pending); }
                @Override public void afterCompletion(int completion) { if (completion != STATUS_COMMITTED) reservation.release(); }
            });
            else pendingSignals.add(pending);
            submitted = true;
        } finally { if (!submitted) reservation.release(); }
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

        String encoded = JsonUtil.objectToString(message); ChannelBinding binding = new ChannelBinding(channel);
        afterCommit(() -> writeEncoded(binding,"server",account.getClientName(),encoded));
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

    /**
     * Tells a departed client's peers that it is gone.
     *
     * <p>Rosters were pushed when a client arrived and never when it left, so the peers of a
     * device that disconnected kept it as online until something else in the tenant logged in. A
     * consumer whose egress had stopped went on sending flows into a session nobody answered.
     *
     * <p>Must run after the client's control channel is unbound, so the roster built here counts it
     * as offline. A client already back on a newer channel was announced by that login and is left
     * alone -- which is also what keeps this safe if it ever ran early.
     */
    public void pushOnLogout(String clientName) {
        if (!peerMeshService.isEnabled() || !StringUtils.hasText(clientName)
                || SessionUtil.getChannel(clientName) != null) {
            return;
        }
        clientAccountService.findClientByName(clientName).ifPresent(account -> {
            for (ClientAccount target : peerMeshService.rosterRefreshTargets(account)) {
                pushRoster(target);
                pushEgress(target);
            }
        });
    }

    @TransactionalEventListener
    public void onClientDeleted(ClientPeerReferences.Deleted event) {
        // The committing thread still owns its JDBC connection here. Queue the refresh so SQLite's
        // one-connection pool is released before any snapshot query needs that connection again.
        deletedClients.add(event);
    }

    @Scheduled(fixedDelay = 100)
    public void refreshDeletedClients() {
        for (int i = 0; i < 64; i++) {
            ClientPeerReferences.Deleted event = deletedClients.poll();
            if (event == null) return;
            try {
                refreshDeletedClient(event);
            } catch (RuntimeException failure) {
                deletedClients.add(event);
                log.warn("[peer-mesh] retrying deleted client refresh tenant={} client={}",
                        event.tenantId(), event.clientId(), failure);
                return;
            }
        }
    }

    private void refreshDeletedClient(ClientPeerReferences.Deleted event) {
        for (PeerMeshSessionView closed : event.closedSessions()) {
            sendClose(closed);
        }
        ClientAccount departed = new ClientAccount();
        departed.setId(event.clientId());
        departed.setTenantId(event.tenantId());
        departed.setClientName(event.clientName());
        pushCatalogs(peerServiceDiscoveryService.withdrawDeletedClient(departed));
        pushCatalogs(peerServiceDiscoveryService.onAuthorizationChanged(event.tenantId()));
        for (ClientAccount account : clientAccountService.listTenantAccounts(event.tenantId())) {
            pushConfig(account);
            pushRoster(account);
            pushEgress(account);
        }
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
        if (transactionActive()) {
            afterCommit(() -> committedAuthorizationRefreshes.put(context.tenant().tenantId(),context));
            return;
        }
        try { refreshCommittedAuthorization(context); }
        catch (RuntimeException failure) { committedAuthorizationRefreshes.put(context.tenant().tenantId(),context); throw failure; }
    }

    @Scheduled(fixedDelayString = "${specus.peer-mesh.authorization-refresh-interval-ms:100}")
    public void refreshCommittedAuthorizations() {
        int count=0;
        for (var entry : committedAuthorizationRefreshes.entrySet()) {
            if (++count > 16) return;
            if (!committedAuthorizationRefreshes.remove(entry.getKey(),entry.getValue())) continue;
            try { refreshCommittedAuthorization(entry.getValue()); }
            catch (RuntimeException failure) {
                committedAuthorizationRefreshes.putIfAbsent(entry.getKey(),entry.getValue());
                log.warn("[peer-mesh] retrying committed authorization refresh tenant={}",entry.getKey());
            }
        }
    }

    private void refreshCommittedAuthorization(ManagementContext context) {
        // Revoke current sessions/cache before publishing derived configuration, rosters or catalogs.
        for (PeerMeshSessionView closed : peerMeshService.closeUnauthorizedSessions(context)) sendClose(closed);
        for (ClientAccount account : clientAccountService.listTenantAccounts(context.tenant())) {
            pushConfig(account);
            pushRoster(account);
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
        PeerControlMessage close = closeMessage(closed,"admin-force-close");
        sendCloseIfOnline(closed.sourceClientName(), close);
        sendCloseIfOnline(closed.targetClientName(), close);
    }

    private PeerControlMessage closeMessage(PeerMeshSessionView closed,String reason) {
        PeerControlMessage close = new PeerControlMessage();
        close.setType(PeerControlMessage.TYPE_CLOSE);
        close.setSessionId(closed.id());
        close.setSourceClientId(closed.sourceClientId());
        close.setSourceClientName(closed.sourceClientName());
        close.setTargetClientId(closed.targetClientId());
        close.setTargetClientName(closed.targetClientName());
        close.setStatus(closed.status());
        close.setReason(reason);
        close.setCreatedAtMillis(System.currentTimeMillis());
        return close;
    }

    private PeerControlMessage parseSignal(String raw) {
        PeerControlMessage signal = JsonUtil.stringToObject(raw, PeerControlMessage.class);
        if (signal == null || !StringUtils.hasText(signal.getType())) {
            throw new IllegalArgumentException("invalid peer signal");
        }
        return signal;
    }

    private boolean shouldOpenSession(PeerControlMessage signal) {
        return signal.getSessionId() == null
                && (PeerControlMessage.TYPE_CANDIDATES.equals(signal.getType())
                || "offer".equals(signal.getType()));
    }

    private void sendSignal(Channel channel, String sourceClientName, String targetClientName, PeerControlMessage signal) {
        String encoded = JsonUtil.objectToString(signal); ChannelBinding binding = new ChannelBinding(channel);
        afterCommit(() -> writeEncoded(binding,sourceClientName,targetClientName,encoded));
    }

    private void writeEncoded(ChannelBinding binding,String sourceClientName,String targetClientName,String encoded) {
        if (!binding.matches(targetClientName)) return;
        MessageResponsePacket response = new MessageResponsePacket();
        response.setMessageType(MessageType.PEER_CONTROL);
        response.setClientName(sourceClientName);
        response.setToClientName(targetClientName);
        response.setMessage(encoded);
        binding.channel().writeAndFlush(response).addListener(future -> {
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
