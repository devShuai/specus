package com.theshuai.tunnelserver.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.channel.ChannelHandlerContext;
import com.theshuai.tunnelserver.management.service.TrafficInspectionService;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;

import java.util.HashMap;
import java.util.Map;

public class RemoteTunnelHandler extends NatCommonHandler {

    private final NatServerHandler tunnelHandler;

    private final int port;
    private final String clientName;
    private final TrafficUsageService trafficUsageService;
    private final TrafficInspectionService trafficInspectionService;

    public RemoteTunnelHandler(NatServerHandler tunnelHandler,
                               int port,
                               String clientName,
                               TrafficUsageService trafficUsageService,
                               TrafficInspectionService trafficInspectionService) {
        this.tunnelHandler = tunnelHandler;
        this.port = port;
        this.clientName = clientName;
        this.trafficUsageService = trafficUsageService;
        this.trafficInspectionService = trafficInspectionService;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
        if (controlCtx == null || !controlCtx.channel().isActive()) {
            ctx.close();
            return;
        }
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.CONNECTED);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", ctx.channel().id().asLongText());
        metaData.put("port", port);
        message.setMetaData(metaData);
        controlCtx.writeAndFlush(message);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DISCONNECTED);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", ctx.channel().id().asLongText());
        message.setMetaData(metaData);
        ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
        if (controlCtx != null && controlCtx.channel().isActive()) {
            controlCtx.writeAndFlush(message);
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
        trafficUsageService.recordTcpDownload(clientName, port, data.length);
        trafficInspectionService.recordTcpFrame(clientName, port, ctx.channel().id().asLongText(),
                TrafficInspectionService.DIRECTION_PUBLIC_TO_CLIENT, remoteAddress(ctx), data);
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DATA);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", ctx.channel().id().asLongText());
        message.setMetaData(metaData);
        message.setData(data);
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
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        tunnelHandler.updateControlAutoReadForExternalWritability();
        super.channelWritabilityChanged(ctx);
    }

    private String remoteAddress(ChannelHandlerContext ctx) {
        return ctx.channel().remoteAddress() == null ? null : ctx.channel().remoteAddress().toString();
    }
}
