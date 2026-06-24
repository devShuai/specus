package com.theshuai.tunnelserver.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.tunnelserver.management.service.TrafficInspectionService;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import io.netty.channel.ChannelHandlerContext;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
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
        trafficInspectionService.releaseTcpStream(ctx.channel().id().asLongText());
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
                TrafficInspectionService.DIRECTION_PUBLIC_TO_CLIENT,
                endpointAddress(ctx.channel().remoteAddress()),
                endpointPort(ctx.channel().remoteAddress()),
                endpointAddress(ctx.channel().localAddress()),
                endpointPort(ctx.channel().localAddress()),
                data);
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

    private String endpointAddress(SocketAddress address) {
        if (address instanceof InetSocketAddress socketAddress) {
            return socketAddress.getAddress() == null
                    ? socketAddress.getHostString()
                    : socketAddress.getAddress().getHostAddress();
        }
        return address == null ? null : address.toString();
    }

    private Integer endpointPort(SocketAddress address) {
        return address instanceof InetSocketAddress socketAddress ? socketAddress.getPort() : null;
    }
}
