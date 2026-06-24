package com.theshuai.common.handler;

import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

@ChannelHandler.Sharable
public class HeartbeatRequestHandler extends SimpleChannelInboundHandler<HeartBeatRequestPacket> {
    public static final HeartbeatRequestHandler INSTANCE = new HeartbeatRequestHandler();

    private HeartbeatRequestHandler() {

    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, HeartBeatRequestPacket heartBeatRequestPacket) throws Exception {
        ctx.writeAndFlush(new HeartBeatResponsePacket());
    }
}
