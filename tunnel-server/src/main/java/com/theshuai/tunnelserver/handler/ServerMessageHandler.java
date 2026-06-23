package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.Packet;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

import static com.theshuai.common.command.Command.LOGOUT_REQUEST;
import static com.theshuai.common.command.Command.MESSAGE_REQUEST;

/**
 * 服务端控制连接的总分发器：根据 packet command 路由到 {@link MessageRequestHandler} /
 * {@link LogoutRequestHandler}。NAT 消息由独立的 {@code NatServerHandler} 处理，这里直接放过。
 */
@ChannelHandler.Sharable
@Component
public class ServerMessageHandler extends SimpleChannelInboundHandler<Packet> {
    private final Map<Byte, SimpleChannelInboundHandler<? extends Packet>> handlerMap;

    public ServerMessageHandler(MessageRequestHandler messageRequestHandler) {
        handlerMap = new HashMap<>();
        handlerMap.put(MESSAGE_REQUEST, messageRequestHandler);
        handlerMap.put(LOGOUT_REQUEST, LogoutRequestHandler.INSTANCE);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Packet packet) throws Exception {
        if (packet instanceof NatMessagePacket) {
            return;
        }
        SimpleChannelInboundHandler<? extends Packet> handler = handlerMap.get(packet.getCommand());
        if (handler != null) {
            handler.channelRead(ctx, packet);
        }
    }
}
