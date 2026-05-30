package com.theshuai.common.handler;

import com.theshuai.common.manager.SyncFutureTaskManager;
import com.theshuai.common.protocol.response.HttpResponsePacket;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

@ChannelHandler.Sharable
public class CustomHttpResponseHandler extends SimpleChannelInboundHandler<HttpResponsePacket> {

    public static final CustomHttpResponseHandler INSTANCE = new CustomHttpResponseHandler();

    private CustomHttpResponseHandler() {
    }

    @Override
    protected void channelRead0(ChannelHandlerContext channelHandlerContext, HttpResponsePacket httpResponsePacket) throws Exception {
        SyncFutureTaskManager.ackSyncMsg(httpResponsePacket);
    }
}
