package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.handler.TcpHalfCloseState;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.ChannelInputShutdownEvent;
import io.netty.channel.socket.DuplexChannel;

public class LocalSpecusHandler extends NatCommonHandler {

    private final NatClientHandler specusHandler;
    private final int streamId;
    private final TcpHalfCloseState closeState = new TcpHalfCloseState();

    public LocalSpecusHandler(NatClientHandler specusHandler, int streamId) {
        this.specusHandler = specusHandler;
        this.streamId = streamId;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        super.channelActive(ctx);
        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx != null && controlCtx.channel().isActive()) {
            StreamFlowController.get(controlCtx.channel()).open(streamId, ctx.channel());
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        byte[] data = (byte[]) msg;
        if (!closeState.canSendLocalData()) {
            protocolViolation(ctx, "local TCP DATA after FIN");
            return;
        }
        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx == null || !controlCtx.channel().isActive()) {
            closeState.reset();
            ctx.close();
            return;
        }
        StreamFlowController.get(controlCtx.channel()).send(streamId, data, ctx.channel(),
                () -> abortAfterFlowReset(ctx));
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        specusHandler.removeLocalHandler(streamId, this);
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
                    streamId, 9, "local TCP channel closed before FIN");
        } else if (controlCtx != null) {
            StreamFlowController.get(controlCtx.channel()).remove(streamId);
        }
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof ChannelInputShutdownEvent) {
            beginLocalFin(ctx);
            return;
        }
        super.userEventTriggered(ctx, evt);
    }

    void writeFromRemote(byte[] data, boolean endStream) {
        ChannelHandlerContext localCtx = ctx;
        if (localCtx == null) {
            specusHandler.resetTcpStream(streamId, 7, "local TCP stream is not active");
            return;
        }
        execute(localCtx, () -> {
            if (!closeState.canReceiveRemoteData()) {
                protocolViolation(localCtx, "remote TCP DATA after FIN");
                return;
            }
            localCtx.writeAndFlush(data).addListener(future -> {
                if (!future.isSuccess()) {
                    resetAndClose(localCtx, 9, "write to local TCP channel failed");
                    return;
                }
                specusHandler.sendTcpWindowUpdate(streamId, data.length);
                if (endStream) {
                    receiveRemoteFinOnEventLoop(localCtx);
                }
            });
            if (!localCtx.channel().isWritable()) {
                specusHandler.pauseTcpControlReads();
            }
        });
    }

    void receiveRemoteFin() {
        ChannelHandlerContext localCtx = ctx;
        if (localCtx == null) {
            specusHandler.resetTcpStream(streamId, 7, "local TCP stream is not active");
            return;
        }
        execute(localCtx, () -> receiveRemoteFinOnEventLoop(localCtx));
    }

    void receiveRemoteReset() {
        closeState.reset();
        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx != null) {
            StreamFlowController.get(controlCtx.channel()).remove(streamId);
        }
        ChannelHandlerContext localCtx = ctx;
        if (localCtx != null) {
            execute(localCtx, localCtx::close);
        }
    }

    TcpHalfCloseState closeState() {
        return closeState;
    }

    private void beginLocalFin(ChannelHandlerContext localCtx) {
        TcpHalfCloseState.Transition transition = closeState.beginLocalFin();
        if (transition != TcpHalfCloseState.Transition.ACCEPTED) {
            return;
        }
        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx == null || !controlCtx.channel().isActive()) {
            closeState.reset();
            localCtx.close();
            return;
        }
        StreamFlowController.get(controlCtx.channel()).finishAsync(streamId, null)
                .whenComplete((ignored, error) -> execute(localCtx, () -> {
                    if (error != null) {
                        resetAndClose(localCtx, 9, "failed to send local TCP FIN");
                        return;
                    }
                    closeState.completeLocalFin();
                    closeIfComplete(localCtx);
                }));
    }

    private void receiveRemoteFinOnEventLoop(ChannelHandlerContext localCtx) {
        TcpHalfCloseState.Transition transition = closeState.receiveRemoteFin();
        if (transition == TcpHalfCloseState.Transition.DUPLICATE) {
            protocolViolation(localCtx, "duplicate remote TCP FIN");
            return;
        }
        if (transition == TcpHalfCloseState.Transition.RESET) {
            return;
        }
        Channel channel = localCtx.channel();
        if (!(channel instanceof DuplexChannel duplexChannel)) {
            protocolViolation(localCtx, "local TCP channel does not support half-close");
            return;
        }
        duplexChannel.shutdownOutput().addListener(future -> {
            if (!future.isSuccess()) {
                resetAndClose(localCtx, 9, "failed to half-close local TCP output");
                return;
            }
            closeState.completeRemoteOutputShutdown();
            closeIfComplete(localCtx);
        });
    }

    private void closeIfComplete(ChannelHandlerContext localCtx) {
        if (closeState.isGracefullyComplete()) {
            localCtx.close();
        }
    }

    private void protocolViolation(ChannelHandlerContext localCtx, String reason) {
        resetAndClose(localCtx, 7, reason);
    }

    private void resetAndClose(ChannelHandlerContext localCtx, long errorCode, String reason) {
        if (closeState.reset()) {
            specusHandler.resetTcpStream(streamId, errorCode, reason);
        }
        localCtx.close();
    }

    private void abortAfterFlowReset(ChannelHandlerContext localCtx) {
        closeState.reset();
        localCtx.close();
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
        specusHandler.updateControlAutoReadForLocalWritability();
        super.channelWritabilityChanged(ctx);
    }
}
