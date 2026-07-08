package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.session.Session;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.service.ClientAccountService;
import com.theshuai.tunnelserver.management.service.PeerMeshService;
import com.theshuai.tunnelserver.management.service.PeerSignalService;
import com.theshuai.tunnelserver.session.SessionUtil;
import com.theshuai.tunnelserver.websocket.ClientMessagesWebSocketHandler;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * 控制连接通用消息分发：依据 messageType 把 {@link MessageRequestPacket} 路由到目标客户端。
 * 服务端会话路由表 ({@link SessionUtil}) 完全是服务端语义，所以本类也住在 tunnel-server。
 */
@ChannelHandler.Sharable
@Component
@Slf4j
public class MessageRequestHandler extends SimpleChannelInboundHandler<MessageRequestPacket> {
    private final PeerSignalService peerSignalService;
    private final ClientAccountService clientAccountService;
    private final PeerMeshService peerMeshService;
    private final ClientMessagesWebSocketHandler clientMessagesWebSocketHandler;

    public MessageRequestHandler(PeerSignalService peerSignalService,
                                 ClientAccountService clientAccountService,
                                 PeerMeshService peerMeshService,
                                 ClientMessagesWebSocketHandler clientMessagesWebSocketHandler) {
        this.peerSignalService = peerSignalService;
        this.clientAccountService = clientAccountService;
        this.peerMeshService = peerMeshService;
        this.clientMessagesWebSocketHandler = clientMessagesWebSocketHandler;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, MessageRequestPacket messageRequestPacket) throws Exception {
        Session session = SessionUtil.getSession(ctx.channel());

        switch (messageRequestPacket.getMessageType()) {
            case CLIENT_TO_CLIENT -> clientToClient(messageRequestPacket, session);
            case CLIENT_TO_SERVER -> clientToServer(messageRequestPacket, session);
            case SERVER_TO_CLIENT -> serverToClient(messageRequestPacket, session);
            case PEER_CONTROL -> peerControl(messageRequestPacket, session);
            default -> log.info("未知消息类型");
        }
    }

    private void peerControl(MessageRequestPacket messageRequestPacket, Session session) {
        try {
            peerSignalService.handle(messageRequestPacket, session);
        } catch (Exception e) {
            log.warn("[peer-mesh] signal rejected from {} to {}: {}",
                    session == null ? "?" : session.getClientName(),
                    messageRequestPacket.getToClientName(),
                    e.getMessage());
        }
    }

    private void clientToClient(MessageRequestPacket messageRequestPacket, Session session) {
        if (session == null || !StringUtils.hasText(session.getClientName())) {
            log.warn("client->client rejected: unauthenticated sender");
            return;
        }
        if (!StringUtils.hasText(messageRequestPacket.getToClientName())) {
            log.warn("client->client rejected: target is empty, source={}", session.getClientName());
            return;
        }
        if (!StringUtils.hasText(messageRequestPacket.getMessage())) {
            log.warn("client->client rejected: message is empty, source={}, target={}",
                    session.getClientName(), messageRequestPacket.getToClientName());
            return;
        }

        ClientAccount source = clientAccountService.findClientByName(session.getClientName())
                .orElse(null);
        String targetName = messageRequestPacket.getToClientName().trim();
        if (source == null || !source.isEnabled()) {
            log.warn("client->client rejected: source account unavailable, source={}", session.getClientName());
            return;
        }
        if (targetName.regionMatches(true, 0, "admin:", 0, "admin:".length())) {
            boolean delivered = clientMessagesWebSocketHandler.deliverFromClient(
                    source, targetName, messageRequestPacket.getMessage());
            log.info("client->admin websocket {}: source={}, target={}",
                    delivered ? "delivered" : "not-delivered",
                    source.getClientName(), targetName);
            return;
        }
        ClientAccount target = clientAccountService.findClientByName(messageRequestPacket.getToClientName().trim())
                .orElse(null);
        if (target == null || !target.isEnabled()) {
            log.warn("client->client rejected: source/target account unavailable, source={}, target={}",
                    session.getClientName(), messageRequestPacket.getToClientName());
            return;
        }
        if (!peerMeshService.canPeer(source, target)) {
            log.warn("client->client rejected: peer access denied, source={}, target={}",
                    source.getClientName(), target.getClientName());
            return;
        }

        MessageResponsePacket messageResponsePacket = new MessageResponsePacket();
        messageResponsePacket.setClientName(source.getClientName());
        messageResponsePacket.setToClientName(target.getClientName());
        messageResponsePacket.setMessageType(MessageType.CLIENT_TO_CLIENT);
        messageResponsePacket.setMessage(messageRequestPacket.getMessage());

        Channel toClientChannel = SessionUtil.getChannel(target.getClientName());

        if (toClientChannel != null && SessionUtil.hasLogin(toClientChannel)) {
            toClientChannel.writeAndFlush(messageResponsePacket).addListener(future -> {
                if (future.isSuccess()) {
                    log.info("client->client fallback delivered: source={}, target={}",
                            source.getClientName(), target.getClientName());
                } else if (future.cause() != null) {
                    log.warn("client->client fallback delivery failed: source={}, target={}, reason={}",
                            source.getClientName(), target.getClientName(), future.cause().getMessage());
                }
            });
        } else {
            log.info("client->client fallback target offline: source={}, target={}",
                    source.getClientName(), target.getClientName());
        }
    }

    private void serverToClient(MessageRequestPacket messageRequestPacket, Session session) {
        log.info("server->client: {}", messageRequestPacket);
    }

    private void clientToServer(MessageRequestPacket messageRequestPacket, Session session) {
        log.info("client->server: {}", messageRequestPacket.getMessage());
    }
}
