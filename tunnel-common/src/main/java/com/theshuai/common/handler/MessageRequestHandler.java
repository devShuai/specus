package com.theshuai.common.handler;

import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.SessionUtil;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

@ChannelHandler.Sharable
@Slf4j
public class MessageRequestHandler extends SimpleChannelInboundHandler<MessageRequestPacket> {
    public static final MessageRequestHandler INSTANCE = new MessageRequestHandler();

    private MessageRequestHandler() {

    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, MessageRequestPacket messageRequestPacket) throws Exception {

        Session session = SessionUtil.getSession(ctx.channel());

        switch (messageRequestPacket.getMessageType()) {
            case CLIENT_TO_CLIENT:
                clientToClient(messageRequestPacket, session);
                break;
            case CLIENT_TO_SERVER:
                clientToServer(messageRequestPacket, session);
                break;
            case SERVER_TO_CLIENT:
                serverToClient(messageRequestPacket, session);
                break;
            default:
                log.info("未知消息类型");
        }
    }

    private void clientToClient(MessageRequestPacket messageRequestPacket, Session session) {
        MessageResponsePacket messageResponsePacket = new MessageResponsePacket();
        messageResponsePacket.setClientName(messageRequestPacket.getClientName());
        messageRequestPacket.setToClientName(messageRequestPacket.getToClientName());
        messageResponsePacket.setMessage(messageRequestPacket.getMessage());

        Channel toClientChannel = SessionUtil.getChannel(messageRequestPacket.getToClientName());

        if (toClientChannel != null && SessionUtil.hasLogin(toClientChannel)) {
            toClientChannel.writeAndFlush(messageResponsePacket).addListener(future -> {
                if (future.isDone()) {
                    log.info("发送结束");
                }
            });
        } else {
            log.info("[" + session.getClientName() + "] 不在线，发送失败!");
        }
    }

    private void serverToClient(MessageRequestPacket messageRequestPacket, Session session) {
        log.info("server->client: " + messageRequestPacket);
    }

    private void clientToServer(MessageRequestPacket messageRequestPacket, Session session) {
        log.info("client->server: " + messageRequestPacket.getMessage());
    }
}
