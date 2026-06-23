package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.tunnelserver.management.service.PeerSignalService;
import com.theshuai.tunnelserver.session.SessionUtil;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * 控制连接通用消息分发：依据 messageType 把 {@link MessageRequestPacket} 路由到目标客户端。
 * 服务端会话路由表 ({@link SessionUtil}) 完全是服务端语义，所以本类也住在 tunnel-server。
 */
@ChannelHandler.Sharable
@Component
@Slf4j
public class MessageRequestHandler extends SimpleChannelInboundHandler<MessageRequestPacket> {
    private final PeerSignalService peerSignalService;

    public MessageRequestHandler(PeerSignalService peerSignalService) {
        this.peerSignalService = peerSignalService;
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
            peerSignalService.forward(messageRequestPacket, session);
        } catch (Exception e) {
            log.warn("[peer-mesh] signal rejected from {} to {}: {}",
                    session == null ? "?" : session.getClientName(),
                    messageRequestPacket.getToClientName(),
                    e.getMessage());
        }
    }

    private void clientToClient(MessageRequestPacket messageRequestPacket, Session session) {
        MessageResponsePacket messageResponsePacket = new MessageResponsePacket();
        messageResponsePacket.setClientName(messageRequestPacket.getClientName());
        messageResponsePacket.setMessage(messageRequestPacket.getMessage());

        Channel toClientChannel = SessionUtil.getChannel(messageRequestPacket.getToClientName());

        if (toClientChannel != null && SessionUtil.hasLogin(toClientChannel)) {
            toClientChannel.writeAndFlush(messageResponsePacket).addListener(future -> {
                if (future.isDone()) {
                    log.info("发送结束");
                }
            });
        } else {
            log.info("[{}] 不在线，发送失败", session == null ? "?" : session.getClientName());
        }
    }

    private void serverToClient(MessageRequestPacket messageRequestPacket, Session session) {
        log.info("server->client: {}", messageRequestPacket);
    }

    private void clientToServer(MessageRequestPacket messageRequestPacket, Session session) {
        log.info("client->server: {}", messageRequestPacket.getMessage());
    }
}
