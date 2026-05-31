package com.theshuai.common.handler;

import com.theshuai.common.manager.DirectHttpFutureManager;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

@ChannelHandler.Sharable
public class DirectHttpResponseHandler extends SimpleChannelInboundHandler<DirectHttpResponsePacket> {
    public static final DirectHttpResponseHandler INSTANCE = new DirectHttpResponseHandler();

    private DirectHttpResponseHandler() {
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DirectHttpResponsePacket packet) {
        DirectHttpFutureManager.ack(packet);
    }
}
