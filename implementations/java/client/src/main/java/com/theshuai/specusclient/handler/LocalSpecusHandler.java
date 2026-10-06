package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.handler.TcpHalfCloseState;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.ChannelInputShutdownEvent;
import io.netty.channel.socket.DuplexChannel;

import java.util.ArrayDeque;
import java.util.concurrent.RejectedExecutionException;

/**
 * One NAT TCP stream's local socket.
 *
 * <p>The stream is published while its connect is still under way, so the data connection never
 * waits on one target. Everything that touches the local socket runs on the local channel's loop,
 * which the connect also completes on: DATA and FIN that arrive before the connect completes are
 * held there, in arrival order, and replayed the moment it succeeds. Their bytes are reserved in
 * the stream's receive window as they arrive, so the hold is bounded by the window the server was
 * granted, like any other unwritten DATA; past it the stream is reset. If the connect fails the
 * held work is dropped and the stream is reset with the reason it always had.
 */
public class LocalSpecusHandler extends NatCommonHandler {

    private final NatClientHandler specusHandler;
    private final int streamId;
    private final TcpHalfCloseState closeState = new TcpHalfCloseState();
    private final StreamReceiveWindow receiveWindow = new StreamReceiveWindow();
    /** The local channel, known from the moment its connect starts, before the stream is published. */
    private volatile Channel channel;

    // Confined to the local channel's loop.
    private boolean connected;
    private final ArrayDeque<Runnable> untilConnected = new ArrayDeque<>();
    /** The latest write to the local socket; a remote FIN shuts the output down only after it. */
    private ChannelFuture lastWrite;
    /** Bytes held while connecting. Written on the loop only; volatile so tests can read it. */
    private volatile int heldBytes;

    public LocalSpecusHandler(NatClientHandler specusHandler, int streamId) {
        this.specusHandler = specusHandler;
        this.streamId = streamId;
    }

    /** Binds the channel whose connect has just started. Called before the stream is published. */
    void connecting(Channel channel) {
        this.channel = channel;
    }

    /**
     * Netty completes the connect promise before it fires channelActive on this channel's own loop,
     * so DATA or FIN replayed or relayed right after the connect can run first. The context is
     * already held from here, which is when the channel registered, long before it is active.
     */
    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        this.ctx = ctx;
        super.handlerAdded(ctx);
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
            protocolViolation("local TCP DATA after FIN");
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

    /**
     * Runs on the local channel's loop when the connect started for this stream completes. On
     * success the work held meanwhile is replayed in arrival order; on failure it is dropped and the
     * stream is reset, unless it already ended (an RST from the server, or an overrun window).
     */
    void connectFinished(ChannelFuture future, String address, int port) {
        if (future.isSuccess() && !closeState.isReset()
                && specusHandler.localTcpConnected(streamId, this)) {
            connected = true;
            heldBytes = 0;
            Runnable held;
            while ((held = untilConnected.pollFirst()) != null) {
                held.run();
            }
            return;
        }
        dropHeld();
        if (!future.isSuccess() && closeState.reset()) {
            specusHandler.localTcpConnectFailed(streamId, this, address, port, future.cause());
        }
        future.channel().close();
    }

    void writeFromRemote(byte[] data, boolean endStream) {
        Channel local = channel;
        if (local == null) {
            specusHandler.resetTcpStream(streamId, 7, "local TCP stream is not active");
            return;
        }
        if (!receiveWindow.reserve(data.length)) {
            execute(local, () -> resetAndClose(8, "pending local TCP data exceeds receive window"));
            return;
        }
        execute(local, () -> whenConnected(data.length, () -> writeOnEventLoop(data, endStream)));
    }

    void receiveRemoteFin() {
        Channel local = channel;
        if (local == null) {
            specusHandler.resetTcpStream(streamId, 7, "local TCP stream is not active");
            return;
        }
        execute(local, () -> whenConnected(0, this::receiveRemoteFinOnEventLoop));
    }

    void receiveRemoteReset() {
        closeState.reset();
        ChannelHandlerContext controlCtx = specusHandler.getCtx();
        if (controlCtx != null) {
            StreamFlowController.get(controlCtx.channel()).remove(streamId);
        }
        Channel local = channel;
        if (local != null) {
            // Closing a channel that is still connecting abandons the connect.
            execute(local, () -> {
                dropHeld();
                local.close();
            });
        }
    }

    TcpHalfCloseState closeState() {
        return closeState;
    }

    /** Bytes of DATA held while the local connect is under way; for tests. */
    int heldBytes() {
        return heldBytes;
    }

    private void whenConnected(int bytes, Runnable work) {
        if (connected) {
            work.run();
            return;
        }
        if (closeState.isReset()) {
            return;
        }
        untilConnected.addLast(work);
        heldBytes += bytes;
    }

    private void dropHeld() {
        untilConnected.clear();
        heldBytes = 0;
    }

    private void writeOnEventLoop(byte[] data, boolean endStream) {
        if (!closeState.canReceiveRemoteData()) {
            protocolViolation("remote TCP DATA after FIN");
            return;
        }
        ChannelFuture write = ctx.writeAndFlush(data);
        lastWrite = write;
        write.addListener(future -> {
            if (!future.isSuccess()) {
                resetAndClose(9, "write to local TCP channel failed");
                return;
            }
            receiveWindow.release(data.length);
            specusHandler.sendStreamWindowUpdate(streamId, data.length);
        });
        if (endStream) {
            receiveRemoteFinOnEventLoop();
        }
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
                .whenComplete((ignored, error) -> execute(localCtx.channel(), () -> {
                    if (error != null) {
                        resetAndClose(9, "failed to send local TCP FIN");
                        return;
                    }
                    closeState.completeLocalFin();
                    closeIfComplete();
                }));
    }

    /**
     * Takes the remote FIN at once, so DATA after it is refused, and shuts the local output down
     * once the writes before it have reached the socket: shutting it down earlier would fail them.
     */
    private void receiveRemoteFinOnEventLoop() {
        TcpHalfCloseState.Transition transition = closeState.receiveRemoteFin();
        if (transition == TcpHalfCloseState.Transition.DUPLICATE) {
            protocolViolation("duplicate remote TCP FIN");
            return;
        }
        if (transition == TcpHalfCloseState.Transition.RESET) {
            return;
        }
        ChannelFuture pending = lastWrite;
        if (pending == null || pending.isDone()) {
            if (pending == null || pending.isSuccess()) {
                shutdownLocalOutput();
            }
            return;
        }
        pending.addListener(future -> {
            if (future.isSuccess()) {
                shutdownLocalOutput();
            }
        });
    }

    private void shutdownLocalOutput() {
        if (closeState.isReset()) {
            return;
        }
        Channel local = ctx.channel();
        if (!(local instanceof DuplexChannel duplexChannel)) {
            protocolViolation("local TCP channel does not support half-close");
            return;
        }
        duplexChannel.shutdownOutput().addListener(future -> {
            if (!future.isSuccess()) {
                resetAndClose(9, "failed to half-close local TCP output");
                return;
            }
            closeState.completeRemoteOutputShutdown();
            closeIfComplete();
        });
    }

    private void closeIfComplete() {
        if (closeState.isGracefullyComplete()) {
            ctx.close();
        }
    }

    private void protocolViolation(String reason) {
        resetAndClose(7, reason);
    }

    private void resetAndClose(long errorCode, String reason) {
        if (closeState.reset()) {
            specusHandler.resetTcpStream(streamId, errorCode, reason);
        }
        dropHeld();
        // The channel, not the context: a stream still connecting may have no context yet.
        Channel local = channel;
        if (local != null) {
            local.close();
        } else if (ctx != null) {
            ctx.close();
        }
    }

    private void abortAfterFlowReset(ChannelHandlerContext localCtx) {
        closeState.reset();
        localCtx.close();
    }

    private static void execute(Channel channel, Runnable task) {
        if (channel.eventLoop().inEventLoop()) {
            task.run();
            return;
        }
        try {
            channel.eventLoop().execute(task);
        } catch (RejectedExecutionException shuttingDown) {
            // The local worker group is shutting down with the client, and the channel with it.
        }
    }
}
