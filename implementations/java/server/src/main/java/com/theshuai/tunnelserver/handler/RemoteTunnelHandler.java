package com.theshuai.tunnelserver.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.tunnelserver.handler.ChannelAttributes.EndpointSnapshot;
import com.theshuai.tunnelserver.management.service.TrafficInspectionService;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import io.netty.channel.ChannelHandlerContext;

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
        // S1.1 一次性把 channelId / endpoint 字符串缓存到 channel attr 上，
        // 之后 channelRead 每帧不再触发 asLongText + getHostAddress。
        ChannelAttributes.initHotPath(ctx.channel());
        String channelId = ChannelAttributes.channelId(ctx.channel());

        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.CONNECTED);
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

        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DISCONNECTED);
        Map<String, Object> metaData = new HashMap<>(2, 0.75f);
        metaData.put("channelId", channelId);
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

        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DATA);
        Map<String, Object> metaData = new HashMap<>(2, 0.75f);
        metaData.put("channelId", channelId);
        message.setMetaData(metaData);
        message.setData(data);
        // 用 attr-cached listener 实例，避免每帧 new lambda；listener 内部
        // 关闭的是 future.channel()（写入端 = 控制连接）失败时；如果想关闭读取端
        // （ctx.channel()），用 closeOnFailureOf(ctx.channel()) 拿到 channel-scoped 单例。
        controlCtx.writeAndFlush(message).addListener(ChannelAttributes.closeOnFailureOf(ctx.channel()));
        if (!controlCtx.channel().isWritable()) {
            ChannelBackpressure.setAutoRead(ctx.channel(), false);
        }
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        tunnelHandler.updateControlAutoReadForExternalWritability();
        super.channelWritabilityChanged(ctx);
    }
}
