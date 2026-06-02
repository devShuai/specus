package com.theshuai.tunnelserver.handler;

import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;

import java.util.HashMap;
import java.util.Map;

@ChannelHandler.Sharable
public class RemoteTunnelHandler extends NatCommonHandler {

    private final NatCommonHandler tunnelHandler;

    private final int port;
    private final String clientName;
    private final TrafficUsageService trafficUsageService;

    public RemoteTunnelHandler(NatServerHandler tunnelHandler, int port, String clientName, TrafficUsageService trafficUsageService) {
        this.tunnelHandler = tunnelHandler;
        this.port = port;
        this.clientName = clientName;
        this.trafficUsageService = trafficUsageService;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.CONNECTED);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", ctx.channel().id().asLongText());
        metaData.put("port", port);
        message.setMetaData(metaData);
        tunnelHandler.getCtx().writeAndFlush(message);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DISCONNECTED);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", ctx.channel().id().asLongText());
        message.setMetaData(metaData);
        tunnelHandler.getCtx().writeAndFlush(message);


    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        byte[] data = (byte[]) msg;
        trafficUsageService.recordDownload(clientName, data.length);
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DATA);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", ctx.channel().id().asLongText());
        message.setMetaData(metaData);
        message.setData(data);
        tunnelHandler.getCtx().writeAndFlush(message);
    }
}
