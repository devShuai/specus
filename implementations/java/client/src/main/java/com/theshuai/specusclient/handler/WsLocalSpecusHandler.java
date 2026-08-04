package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.WebSocketSpecusFrame;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.util.ReferenceCountUtil;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 客户端侧本地 WebSocket 隧道 handler：把本地 WS 服务的入站帧封装成 NAT {@code DATA} 帧写回
 * 控制连接，channel 关闭时发 {@code DISCONNECTED}。
 *
 * <p>帧类型前缀约定（与服务端 {@code WebSocketSpecusHandler} 对齐）：
 * <ul>
 *   <li>{@code 0x01} TextFrame</li>
 *   <li>{@code 0x02} BinaryFrame</li>
 * </ul>
 * Ping/Pong/Close 由前置的 frame-preserving protocol handler 透传到这里，并和 data frame
 * 一样使用 SWS2；这样 upstream 与公网 WebSocket peer 才是彼此的控制帧端点。
 *
 * <p>握手完成通过拦截 {@link WebSocketClientProtocolHandler.ClientHandshakeStateEvent#HANDSHAKE_COMPLETE}
 * 事件感知，完成后把自己注册进 {@link NatClientHandler} 的 wsLocalChannels，让后续 DATA 帧能路由进来。
 */
public class WsLocalSpecusHandler extends ChannelInboundHandlerAdapter {
    static final long CLOSE_CREDIT_TIMEOUT_MILLIS = 5_000;

    private final NatClientHandler specusHandler;
    private final int streamId;
    private final String remoteChannelId;
    private final long closeCreditTimeoutMillis;
    private final AtomicBoolean terminationStarted = new AtomicBoolean();
    private volatile boolean registered;

    public WsLocalSpecusHandler(NatClientHandler specusHandler, int streamId, String remoteChannelId) {
        this(specusHandler, streamId, remoteChannelId, CLOSE_CREDIT_TIMEOUT_MILLIS);
    }

    WsLocalSpecusHandler(NatClientHandler specusHandler, int streamId, String remoteChannelId,
                         long closeCreditTimeoutMillis) {
        this.specusHandler = specusHandler;
        this.streamId = streamId;
        this.remoteChannelId = remoteChannelId;
        this.closeCreditTimeoutMillis = Math.max(1, closeCreditTimeoutMillis);
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt == WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE) {
            registered = specusHandler.registerWsLocalChannel(streamId, ctx);
            if (registered) {
                StreamFlowController.get(specusHandler.getCtx().channel()).open(streamId, ctx.channel());
                specusHandler.syncLocalReadWithControl(ctx.channel());
            } else {
                // 控制连接已断开，关掉本地 WS
                ctx.close();
                return;
            }
        }
        super.userEventTriggered(ctx, evt);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof WebSocketFrame frame)) {
            // 握手响应等非帧消息由 handshaker 处理，这里不接管
            super.channelRead(ctx, msg);
            return;
        }
        try {
            ChannelHandlerContext controlCtx = specusHandler.getCtx();
            if (controlCtx == null || !controlCtx.channel().isActive()) {
                ctx.close();
                return;
            }
            int opcode = opcode(frame);
            ByteBuf payload = frame.content();
            byte[] data;
            int closeCode = 0;
            if (frame instanceof CloseWebSocketFrame close) {
                closeCode = Math.max(0, close.statusCode());
                data = close.reasonText().getBytes(StandardCharsets.UTF_8);
            } else {
                data = new byte[payload.readableBytes()];
                payload.getBytes(payload.readerIndex(), data);
            }
            if (opcode == WebSocketSpecusFrame.OPCODE_CLOSE) {
                sendClose(controlCtx, ctx, frame.isFinalFragment(), frame.rsv(), closeCode, data);
            } else {
                sendChunked(controlCtx, ctx, opcode, frame.isFinalFragment(), frame.rsv(), closeCode, data);
            }
        } finally {
            ReferenceCountUtil.release(frame);
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        // 只有握手成功注册过的流才需要通知服务端 DISCONNECTED；握手未完成就断开时，
        // NatClientHandler.processWsConnected 已经发过 DISCONNECTED。
        if (registered) {
            specusHandler.removeWsLocalHandler(streamId, this);
            ChannelHandlerContext controlCtx = specusHandler.getCtx();
            if (terminationStarted.compareAndSet(false, true)
                    && controlCtx != null && controlCtx.channel().isActive()) {
                StreamFlowController.get(controlCtx.channel()).finish(streamId);
            }
        } else {
            specusHandler.failPendingWsStream(streamId, "websocket handshake failed");
        }
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        specusHandler.updateControlAutoReadForLocalWritability();
        super.channelWritabilityChanged(ctx);
    }

    /** 由 {@link NatClientHandler#processData} 调用：服务端回送的 DATA 帧还原成 WS 帧写本地 Channel。 */
    public void writeFrame(ChannelHandlerContext localCtx, byte[] payload) {
        try {
            WebSocketSpecusFrame specusFrame = WebSocketSpecusFrame.decode(payload);
            ByteBuf buf = localCtx.alloc().buffer(specusFrame.payload().length);
            buf.writeBytes(specusFrame.payload());
            WebSocketFrame frame = switch (specusFrame.opcode()) {
                case WebSocketSpecusFrame.OPCODE_TEXT ->
                        new TextWebSocketFrame(specusFrame.finalFragment(), specusFrame.rsv(), buf);
                case WebSocketSpecusFrame.OPCODE_BINARY ->
                        new BinaryWebSocketFrame(specusFrame.finalFragment(), specusFrame.rsv(), buf);
                case WebSocketSpecusFrame.OPCODE_CONTINUATION ->
                        new ContinuationWebSocketFrame(specusFrame.finalFragment(), specusFrame.rsv(), buf);
                case WebSocketSpecusFrame.OPCODE_PING -> new PingWebSocketFrame(buf);
                case WebSocketSpecusFrame.OPCODE_PONG -> new PongWebSocketFrame(buf);
                case WebSocketSpecusFrame.OPCODE_CLOSE -> {
                    buf.release();
                    yield new CloseWebSocketFrame(specusFrame.finalFragment(), specusFrame.rsv(),
                            specusFrame.closeCode(), new String(specusFrame.payload(), StandardCharsets.UTF_8));
                }
                default -> throw new IllegalArgumentException("unsupported SWS2 opcode");
            };
            localCtx.writeAndFlush(frame).addListener(future -> {
                if (!future.isSuccess()) {
                    localCtx.close();
                }
            });
        } catch (RuntimeException error) {
            localCtx.close();
        }
    }

    private void sendChunked(ChannelHandlerContext controlCtx, ChannelHandlerContext localCtx,
                             int opcode, boolean finalFragment, int rsv, int closeCode, byte[] payload) {
        int offset = 0;
        boolean first = true;
        do {
            int length = Math.min(WebSocketSpecusFrame.MAX_PAYLOAD_BYTES, payload.length - offset);
            byte[] chunk = new byte[length];
            System.arraycopy(payload, offset, chunk, 0, length);
            offset += length;
            boolean last = offset == payload.length;
            int chunkOpcode = first ? opcode : WebSocketSpecusFrame.OPCODE_CONTINUATION;
            WebSocketSpecusFrame encoded = new WebSocketSpecusFrame(
                    chunkOpcode, finalFragment && last, first ? rsv : 0,
                    first ? closeCode : 0, chunk);
            StreamFlowController.get(controlCtx.channel()).sendAtomic(
                    streamId, encoded.encode(), localCtx.channel(), localCtx::close);
            first = false;
        } while (offset < payload.length);
    }

    private void sendClose(ChannelHandlerContext controlCtx, ChannelHandlerContext localCtx,
                           boolean finalFragment, int rsv, int closeCode, byte[] payload) {
        if (!terminationStarted.compareAndSet(false, true)) {
            return;
        }
        byte[] close = new WebSocketSpecusFrame(WebSocketSpecusFrame.OPCODE_CLOSE,
                finalFragment, rsv, closeCode, payload).encode();
        StreamFlowController flow = StreamFlowController.get(controlCtx.channel());
        CompletableFuture<Void> sequence = flow.sendAtomicAsync(
                        streamId, close, localCtx.channel(), null)
                .thenCompose(ignored -> flow.finishAsync(streamId, null));
        var timeout = controlCtx.executor().schedule(
                () -> sequence.completeExceptionally(
                        new TimeoutException("websocket close credit timeout")),
                closeCreditTimeoutMillis, TimeUnit.MILLISECONDS);
        sequence.whenComplete((ignored, error) -> {
            timeout.cancel(false);
            if (error != null) {
                Throwable cause = unwrap(error);
                String reason = cause instanceof TimeoutException
                        ? "websocket close credit timeout"
                        : "websocket close send failed";
                flow.reset(streamId, 8, reason);
            }
            specusHandler.removeWsLocalHandler(streamId, this);
            localCtx.close();
        });
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while (current instanceof CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static int opcode(WebSocketFrame frame) {
        if (frame instanceof TextWebSocketFrame) return WebSocketSpecusFrame.OPCODE_TEXT;
        if (frame instanceof BinaryWebSocketFrame) return WebSocketSpecusFrame.OPCODE_BINARY;
        if (frame instanceof ContinuationWebSocketFrame) return WebSocketSpecusFrame.OPCODE_CONTINUATION;
        if (frame instanceof CloseWebSocketFrame) return WebSocketSpecusFrame.OPCODE_CLOSE;
        if (frame instanceof PingWebSocketFrame) return WebSocketSpecusFrame.OPCODE_PING;
        if (frame instanceof PongWebSocketFrame) return WebSocketSpecusFrame.OPCODE_PONG;
        throw new IllegalArgumentException("unsupported WebSocket frame: " + frame.getClass().getSimpleName());
    }
}
