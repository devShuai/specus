package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.channel.ChannelHandlerContext;

import java.util.HashMap;
import java.util.Map;

public class LocalTunnelHandler extends NatCommonHandler {

    private final NatClientHandler tunnelHandler;
    private final String remoteChannelId;

    public LocalTunnelHandler(NatClientHandler tunnelHandler, String remoteChannelId) {
        this.tunnelHandler = tunnelHandler;
        this.remoteChannelId = remoteChannelId;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        byte[] data = (byte[]) msg;
        ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
        if (controlCtx == null || !controlCtx.channel().isActive()) {
            ctx.close();
            return;
        }
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DATA);
        message.setData(data);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", remoteChannelId);
        message.setMetaData(metaData);
        controlCtx.writeAndFlush(message).addListener(future -> {
            if (!future.isSuccess()) {
                ctx.close();
            }
        });
        if (!controlCtx.channel().isWritable()) {
            ChannelBackpressure.setAutoRead(ctx.channel(), false);
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        tunnelHandler.removeLocalHandler(remoteChannelId, this);
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DISCONNECTED);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", remoteChannelId);
        message.setMetaData(metaData);
        ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
        if (controlCtx != null && controlCtx.channel().isActive()) {
            controlCtx.writeAndFlush(message);
        }
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        tunnelHandler.updateControlAutoReadForLocalWritability();
        super.channelWritabilityChanged(ctx);
    }
}
