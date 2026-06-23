package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
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
    public void forward(MessageRequestPacket request, Session session) {
        if (!peerMeshService.isEnabled()) {
            throw new IllegalStateException("peer mesh is disabled");
        }
        if (session == null || !StringUtils.hasText(session.getClientName())) {
            throw new IllegalArgumentException("peer signal requires authenticated client");
        }
        if (!StringUtils.hasText(request.getToClientName())) {
            throw new IllegalArgumentException("toClientName is required");
        }

        ClientAccount source = clientAccountService.findClientByName(session.getClientName())
                .orElseThrow(() -> new IllegalArgumentException("source client not found: " + session.getClientName()));
        ClientAccount target = clientAccountService.findClientByName(request.getToClientName().trim())
                .orElseThrow(() -> new IllegalArgumentException("target client not found: " + request.getToClientName()));
        if (!peerMeshService.canPeer(source, target)) {
            throw new IllegalArgumentException("peer access denied");
        }

        Channel targetChannel = SessionUtil.getChannel(target.getClientName());
        if (targetChannel == null || !SessionUtil.hasLogin(targetChannel)) {
            throw new IllegalStateException("target peer is offline: " + target.getClientName());
        }

        MessageResponsePacket response = new MessageResponsePacket();
        response.setMessageType(MessageType.PEER_CONTROL);
        response.setClientName(source.getClientName());
        response.setToClientName(target.getClientName());
        response.setMessage(enrichMessage(request.getMessage(), source, target));
        targetChannel.writeAndFlush(response).addListener(future -> {
            if (!future.isSuccess()) {
                log.warn("[peer-mesh] signal write failed source={} target={}",
                        source.getClientName(), target.getClientName(), future.cause());
            }
        });
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
        message.put("type", "roster");
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

    private String enrichMessage(String raw, ClientAccount source, ClientAccount target) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("type", "signal");
        envelope.put("sourceClientId", source.getId());
        envelope.put("sourceClientName", source.getClientName());
        envelope.put("targetClientId", target.getId());
        envelope.put("targetClientName", target.getClientName());
        envelope.put("payload", raw == null ? "" : raw);
        return JsonUtil.objectToString(envelope);
    }
}
