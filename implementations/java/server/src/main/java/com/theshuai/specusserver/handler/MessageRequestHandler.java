package com.theshuai.specusserver.handler;

import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.ClientMessageRelayService;
import com.theshuai.specusserver.management.service.PeerSignalService;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.websocket.ClientMessagesWebSocketHandler;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * 控制连接通用消息分发：依据 messageType 把 {@link MessageRequestPacket} 路由到目标客户端。
 * 服务端会话路由表 ({@link SessionUtil}) 完全是服务端语义，所以本类也住在 specus-server。
 */
@ChannelHandler.Sharable
@Component
@Slf4j
public class MessageRequestHandler extends SimpleChannelInboundHandler<MessageRequestPacket> {
    private final PeerSignalService peerSignalService;
    private final ClientAccountService clientAccountService;
    private final ClientMessageRelayService clientMessageRelayService;
    private final ClientMessagesWebSocketHandler clientMessagesWebSocketHandler;

    public MessageRequestHandler(PeerSignalService peerSignalService,
                                 ClientAccountService clientAccountService,
                                 ClientMessageRelayService clientMessageRelayService,
                                 ClientMessagesWebSocketHandler clientMessagesWebSocketHandler) {
        this.peerSignalService = peerSignalService;
        this.clientAccountService = clientAccountService;
        this.clientMessageRelayService = clientMessageRelayService;
        this.clientMessagesWebSocketHandler = clientMessagesWebSocketHandler;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, MessageRequestPacket messageRequestPacket) throws Exception {
        Session session = SessionUtil.getSession(ctx.channel());

        switch (messageRequestPacket.getMessageType()) {
            case CLIENT_TO_CLIENT -> clientToClient(messageRequestPacket, session, ctx.channel());
            case CLIENT_TO_SERVER -> clientToServer(messageRequestPacket, session);
            case SERVER_TO_CLIENT -> serverToClient(messageRequestPacket, session);
            case PEER_CONTROL -> peerControl(messageRequestPacket, session, ctx.channel());
            default -> log.info("未知消息类型");
        }
    }

    private void peerControl(MessageRequestPacket messageRequestPacket, Session session, Channel incoming) {
        try {
            peerSignalService.handle(messageRequestPacket, session, incoming);
        } catch (Exception e) {
            log.warn("[peer-mesh] signal rejected from {} to {}: {}",
                    session == null ? "?" : session.getClientName(),
                    messageRequestPacket.getToClientName(),
                    e.getMessage());
        }
    }

    private void clientToClient(MessageRequestPacket messageRequestPacket, Session session, Channel incoming) {
        if (session == null || !StringUtils.hasText(session.getClientName()) || !incoming.isActive()
                || SessionUtil.getChannel(session.getClientName()) != incoming || SessionUtil.getSession(incoming) != session) {
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

        String targetName = messageRequestPacket.getToClientName().trim();
        if (!targetName.regionMatches(true, 0, "admin:", 0, "admin:".length())) {
            try {
                clientMessageRelayService.submit(messageRequestPacket, session, incoming);
            } catch (RuntimeException rejected) {
                log.warn("client->client rejected: source={}, target={}, reason={}", session.getClientName(), targetName, rejected.getClass().getSimpleName());
            }
            return;
        }
        ClientAccount source = clientAccountService.findClientByName(session.getClientName()).orElse(null);
        if (source == null || !source.isEnabled() || !source.getTenantId().equals(incoming.attr(ServerAttributes.TENANT_ID).get())) {
            log.warn("client->client rejected: source account unavailable, source={}", session.getClientName());
            return;
        }
        boolean delivered = clientMessagesWebSocketHandler.deliverFromClient(
                source, targetName, messageRequestPacket.getMessage(), incoming);
        log.info("client->admin websocket {}: source={}, target={}",
                delivered ? "accepted" : "not-accepted", source.getClientName(), targetName);
    }

    private void serverToClient(MessageRequestPacket messageRequestPacket, Session session) {
        log.info("server->client: {}", messageRequestPacket);
    }

    private void clientToServer(MessageRequestPacket messageRequestPacket, Session session) {
        log.info("client->server: {}", messageRequestPacket.getMessage());
    }
}
