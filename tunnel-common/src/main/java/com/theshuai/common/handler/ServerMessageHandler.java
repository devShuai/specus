package com.theshuai.common.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.Packet;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

import java.util.HashMap;
import java.util.Map;

import static com.theshuai.common.command.Command.*;


@ChannelHandler.Sharable
public class ServerMessageHandler extends SimpleChannelInboundHandler<Packet> {
    public static final ServerMessageHandler INSTANCE = new ServerMessageHandler();

    private final Map<Byte, SimpleChannelInboundHandler<? extends Packet>> handlerMap;

    private ServerMessageHandler() {
        handlerMap = new HashMap<>();

        handlerMap.put(MESSAGE_REQUEST, MessageRequestHandler.INSTANCE);
        handlerMap.put(LOGOUT_REQUEST, LogoutRequestHandler.INSTANCE);
        handlerMap.put(HTTP_RESPONSE, CustomHttpResponseHandler.INSTANCE);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Packet packet) throws Exception {
        if (!(packet instanceof NatMessagePacket)) {
            handlerMap.get(packet.getCommand()).channelRead(ctx, packet);
        }
    }
}