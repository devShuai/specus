package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.PeerMeshSessionView;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class PeerSignalService {
    private final ClientAccountService clientAccountService;
    private final PeerMeshService peerMeshService;

    public PeerSignalService(ClientAccountService clientAccountService, PeerMeshService peerMeshService) {
        this.clientAccountService = clientAccountService;
        this.peerMeshService = peerMeshService;
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
        return closedSessions;
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
