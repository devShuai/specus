package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.channel.ChannelHandlerContext;

public class LocalTunnelHandler extends NatCommonHandler {

    private final NatClientHandler tunnelHandler;
    private final int streamId;

    public LocalTunnelHandler(NatClientHandler tunnelHandler, int streamId) {
        this.tunnelHandler = tunnelHandler;
        this.streamId = streamId;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        super.channelActive(ctx);
        ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
        if (controlCtx != null && controlCtx.channel().isActive()) {
            StreamFlowController.get(controlCtx.channel()).open(streamId, ctx.channel());
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        byte[] data = (byte[]) msg;
        ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
        if (controlCtx == null || !controlCtx.channel().isActive()) {
            ctx.close();
            return;
        }
        StreamFlowController.get(controlCtx.channel()).send(streamId, data, ctx.channel(), ctx::close);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        tunnelHandler.removeLocalHandler(streamId, this);
        ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
        if (controlCtx != null && controlCtx.channel().isActive()) {
            StreamFlowController.get(controlCtx.channel()).finish(streamId);
        }
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        tunnelHandler.updateControlAutoReadForLocalWritability();
        super.channelWritabilityChanged(ctx);
    }
}
