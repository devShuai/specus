package com.theshuai.specusserver.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusserver.handler.ChannelAttributes.EndpointSnapshot;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import io.netty.channel.ChannelHandlerContext;

import java.util.HashMap;
import java.util.Map;

public class RemoteSpecusHandler extends NatCommonHandler {

    private final NatServerHandler specusHandler;

    private final int streamId;

    private final int port;
    private final String clientName;
    private final TrafficUsageService trafficUsageService;
    private final TrafficInspectionService trafficInspectionService;

    public RemoteSpecusHandler(NatServerHandler specusHandler,
                               int streamId,
                               int port,
                               String clientName,
                               TrafficUsageService trafficUsageService,
                               TrafficInspectionService trafficInspectionService) {
        this.specusHandler = specusHandler;
        this.streamId = streamId;
        this.port = port;
        this.clientName = clientName;
        this.trafficUsageService = trafficUsageService;
        this.trafficInspectionService = trafficInspectionService;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx == null || !controlCtx.channel().isActive()) {
            ctx.close();
            return;
        }
        // S1.1 一次性把 channelId / endpoint 字符串缓存到 channel attr 上，
        // 之后 channelRead 每帧不再触发 asLongText + getHostAddress。
        ChannelAttributes.initHotPath(ctx.channel());
        String channelId = ChannelAttributes.channelId(ctx.channel());
        StreamFlowController.get(controlCtx.channel()).open(streamId, ctx.channel());

        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.OPEN);
        message.setStreamId(streamId);
        // 元数据只有 2 个 key，给一个匹配大小的 HashMap 容量，避免默认 16 桶的浪费
        Map<String, Object> metaData = new HashMap<>(4, 0.75f);
        metaData.put("channelId", channelId);
        metaData.put("port", port);
        message.setMetaData(metaData);
        controlCtx.writeAndFlush(message);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        String channelId = ChannelAttributes.channelId(ctx.channel());
        trafficInspectionService.releaseTcpStream(channelId);

        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx != null && controlCtx.channel().isActive()) {
            StreamFlowController.get(controlCtx.channel()).finish(streamId);
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        byte[] data = (byte[]) msg;
        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx == null || !controlCtx.channel().isActive()) {
            ctx.close();
            return;
        }
        // 读 channel-level 缓存的 channelId / endpoint，替代每帧 asLongText() + getHostAddress()
        String channelId = ChannelAttributes.channelId(ctx.channel());
        EndpointSnapshot remote = ChannelAttributes.remoteEndpoint(ctx.channel());
        EndpointSnapshot local = ChannelAttributes.localEndpoint(ctx.channel());

        trafficUsageService.recordTcpDownload(clientName, port, data.length);
        trafficInspectionService.recordTcpFrame(clientName, port, channelId,
                TrafficInspectionService.DIRECTION_PUBLIC_TO_CLIENT,
                remote.address(),
                remote.port(),
                local.address(),
                local.port(),
                data);

        StreamFlowController.get(controlCtx.channel()).send(streamId, data, ctx.channel(), ctx::close);
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        specusHandler.updateControlAutoReadForExternalWritability();
        super.channelWritabilityChanged(ctx);
    }
}
