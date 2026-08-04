package com.theshuai.specusserver.handler;

import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.handler.TcpHalfCloseState;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusserver.handler.ChannelAttributes.EndpointSnapshot;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.ChannelInputShutdownEvent;
import io.netty.channel.socket.DuplexChannel;

import java.util.HashMap;
import java.util.Map;

public class RemoteSpecusHandler extends NatCommonHandler {

    private final NatServerHandler specusHandler;

    private final int streamId;

    private final int port;
    private final String clientName;
    private final TrafficUsageService trafficUsageService;
    private final TrafficInspectionService trafficInspectionService;
    private final TcpHalfCloseState closeState = new TcpHalfCloseState();

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
        super.channelActive(ctx);
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
        if (closeState.isReset() || closeState.isGracefulClosing() || closeState.isGracefullyComplete()) {
            if (closeState.isReset() && controlCtx != null) {
                StreamFlowController.get(controlCtx.channel()).remove(streamId);
            }
            return;
        }
        closeState.reset();
        if (controlCtx != null && controlCtx.channel().isActive()) {
            StreamFlowController.get(controlCtx.channel()).reset(
                    streamId, 9, "external TCP channel closed before FIN");
        } else if (controlCtx != null) {
            StreamFlowController.get(controlCtx.channel()).remove(streamId);
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        byte[] data = (byte[]) msg;
        if (!closeState.canSendLocalData()) {
            protocolViolation(ctx, "external TCP DATA after FIN");
            return;
        }
        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx == null || !controlCtx.channel().isActive()) {
            closeState.reset();
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

        StreamFlowController.get(controlCtx.channel()).send(streamId, data, ctx.channel(),
                () -> abortAfterFlowReset(ctx));
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof ChannelInputShutdownEvent) {
            beginLocalFin(ctx);
            return;
        }
        super.userEventTriggered(ctx, evt);
    }

    void writeFromClient(byte[] data, boolean endStream) {
        ChannelHandlerContext externalCtx = ctx;
        if (externalCtx == null) {
            specusHandler.resetTcpStream(streamId, 7, "external TCP stream is not active");
            return;
        }
        execute(externalCtx, () -> {
            if (!closeState.canReceiveRemoteData()) {
                protocolViolation(externalCtx, "client TCP DATA after FIN");
                return;
            }
            String channelId = ChannelAttributes.channelId(externalCtx.channel());
            EndpointSnapshot local = ChannelAttributes.localEndpoint(externalCtx.channel());
            EndpointSnapshot remote = ChannelAttributes.remoteEndpoint(externalCtx.channel());
            trafficUsageService.recordTcpUpload(clientName, port, data.length);
            trafficInspectionService.recordTcpFrame(clientName, port, channelId,
                    TrafficInspectionService.DIRECTION_CLIENT_TO_PUBLIC,
                    local.address(), local.port(), remote.address(), remote.port(), data);

            externalCtx.writeAndFlush(data).addListener(future -> {
                if (!future.isSuccess()) {
                    resetAndClose(externalCtx, 9, "write to external TCP channel failed");
                    return;
                }
                specusHandler.sendTcpWindowUpdate(streamId, data.length);
                if (endStream) {
                    receiveClientFinOnEventLoop(externalCtx);
                }
            });
            if (!externalCtx.channel().isWritable()) {
                specusHandler.pauseTcpControlReads();
            }
        });
    }

    void receiveClientFin() {
        ChannelHandlerContext externalCtx = ctx;
        if (externalCtx == null) {
            specusHandler.resetTcpStream(streamId, 7, "external TCP stream is not active");
            return;
        }
        execute(externalCtx, () -> receiveClientFinOnEventLoop(externalCtx));
    }

    void receiveClientReset() {
        closeState.reset();
        specusHandler.abortTcpStream(streamId);
        ChannelHandlerContext externalCtx = ctx;
        if (externalCtx != null) {
            execute(externalCtx, externalCtx::close);
        }
    }

    TcpHalfCloseState closeState() {
        return closeState;
    }

    private void beginLocalFin(ChannelHandlerContext externalCtx) {
        TcpHalfCloseState.Transition transition = closeState.beginLocalFin();
        if (transition != TcpHalfCloseState.Transition.ACCEPTED) {
            return;
        }
        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx == null || !controlCtx.channel().isActive()) {
            closeState.reset();
            externalCtx.close();
            return;
        }
        StreamFlowController.get(controlCtx.channel()).finishAsync(streamId, null)
                .whenComplete((ignored, error) -> execute(externalCtx, () -> {
                    if (error != null) {
                        resetAndClose(externalCtx, 9, "failed to send external TCP FIN");
                        return;
                    }
                    closeState.completeLocalFin();
                    closeIfComplete(externalCtx);
                }));
    }

    private void receiveClientFinOnEventLoop(ChannelHandlerContext externalCtx) {
        TcpHalfCloseState.Transition transition = closeState.receiveRemoteFin();
        if (transition == TcpHalfCloseState.Transition.DUPLICATE) {
            protocolViolation(externalCtx, "duplicate client TCP FIN");
            return;
        }
        if (transition == TcpHalfCloseState.Transition.RESET) {
            return;
        }
        Channel channel = externalCtx.channel();
        if (!(channel instanceof DuplexChannel duplexChannel)) {
            protocolViolation(externalCtx, "external TCP channel does not support half-close");
            return;
        }
        duplexChannel.shutdownOutput().addListener(future -> {
            if (!future.isSuccess()) {
                resetAndClose(externalCtx, 9, "failed to half-close external TCP output");
                return;
            }
            closeState.completeRemoteOutputShutdown();
            closeIfComplete(externalCtx);
        });
    }

    private void closeIfComplete(ChannelHandlerContext externalCtx) {
        if (closeState.isGracefullyComplete()) {
            externalCtx.close();
        }
    }

    private void protocolViolation(ChannelHandlerContext externalCtx, String reason) {
        resetAndClose(externalCtx, 7, reason);
    }

    private void resetAndClose(ChannelHandlerContext externalCtx, long errorCode, String reason) {
        if (closeState.reset()) {
            specusHandler.resetTcpStream(streamId, errorCode, reason);
        }
        externalCtx.close();
    }

    private void abortAfterFlowReset(ChannelHandlerContext externalCtx) {
        closeState.reset();
        externalCtx.close();
    }

    private static void execute(ChannelHandlerContext ctx, Runnable task) {
        if (ctx.executor().inEventLoop()) {
            task.run();
        } else {
            ctx.executor().execute(task);
        }
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        specusHandler.updateControlAutoReadForExternalWritability();
        super.channelWritabilityChanged(ctx);
    }
}
