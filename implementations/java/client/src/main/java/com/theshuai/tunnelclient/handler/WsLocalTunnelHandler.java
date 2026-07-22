package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.WebSocketTunnelFrame;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.websocketx.*;

import java.nio.charset.StandardCharsets;

/**
 * 客户端侧本地 WebSocket 隧道 handler：把本地 WS 服务的入站帧封装成 NAT {@code DATA} 帧写回
 * 控制连接，channel 关闭时发 {@code DISCONNECTED}。
 *
 * <p>帧类型前缀约定（与服务端 {@code WebSocketTunnelHandler} 对齐）：
 * <ul>
 *   <li>{@code 0x01} TextFrame</li>
 *   <li>{@code 0x02} BinaryFrame</li>
 * </ul>
 * Ping/Pong 由本地 WS 客户端栈自动处理，不进 DATA 帧。
 *
 * <p>握手完成通过拦截 {@link WebSocketClientProtocolHandler.ClientHandshakeStateEvent#HANDSHAKE_COMPLETE}
 * 事件感知，完成后把自己注册进 {@link NatClientHandler} 的 wsLocalChannels，让后续 DATA 帧能路由进来。
 */
public class WsLocalTunnelHandler extends ChannelInboundHandlerAdapter {
    private final NatClientHandler tunnelHandler;
    private final int streamId;
    private final String remoteChannelId;
    private volatile boolean registered;

    public WsLocalTunnelHandler(NatClientHandler tunnelHandler, int streamId, String remoteChannelId) {
        this.tunnelHandler = tunnelHandler;
        this.streamId = streamId;
        this.remoteChannelId = remoteChannelId;
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt == WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE) {
            registered = tunnelHandler.registerWsLocalChannel(streamId, ctx);
            if (registered) {
                StreamFlowController.get(tunnelHandler.getCtx().channel()).open(streamId, ctx.channel());
                tunnelHandler.syncLocalReadWithControl(ctx.channel());
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
        ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
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
        sendChunked(controlCtx, ctx, opcode, frame.isFinalFragment(), frame.rsv(), closeCode, data);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        // 只有握手成功注册过的流才需要通知服务端 DISCONNECTED；握手未完成就断开时，
        // NatClientHandler.processWsConnected 已经发过 DISCONNECTED。
        if (registered) {
            tunnelHandler.removeWsLocalHandler(streamId, this);
            ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
            if (controlCtx != null && controlCtx.channel().isActive()) {
                StreamFlowController.get(controlCtx.channel()).finish(streamId);
            }
        }
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        tunnelHandler.updateControlAutoReadForLocalWritability();
        super.channelWritabilityChanged(ctx);
    }

    /** 由 {@link NatClientHandler#processData} 调用：服务端回送的 DATA 帧还原成 WS 帧写本地 Channel。 */
    public void writeFrame(ChannelHandlerContext localCtx, byte[] payload) {
        try {
            WebSocketTunnelFrame tunnelFrame = WebSocketTunnelFrame.decode(payload);
            ByteBuf buf = localCtx.alloc().buffer(tunnelFrame.payload().length);
            buf.writeBytes(tunnelFrame.payload());
            WebSocketFrame frame = switch (tunnelFrame.opcode()) {
                case WebSocketTunnelFrame.OPCODE_TEXT ->
                        new TextWebSocketFrame(tunnelFrame.finalFragment(), tunnelFrame.rsv(), buf);
                case WebSocketTunnelFrame.OPCODE_BINARY ->
                        new BinaryWebSocketFrame(tunnelFrame.finalFragment(), tunnelFrame.rsv(), buf);
                case WebSocketTunnelFrame.OPCODE_CONTINUATION ->
                        new ContinuationWebSocketFrame(tunnelFrame.finalFragment(), tunnelFrame.rsv(), buf);
                case WebSocketTunnelFrame.OPCODE_PING -> new PingWebSocketFrame(buf);
                case WebSocketTunnelFrame.OPCODE_PONG -> new PongWebSocketFrame(buf);
                case WebSocketTunnelFrame.OPCODE_CLOSE -> {
                    buf.release();
                    yield new CloseWebSocketFrame(tunnelFrame.finalFragment(), tunnelFrame.rsv(),
                            tunnelFrame.closeCode(), new String(tunnelFrame.payload(), StandardCharsets.UTF_8));
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
            int length = Math.min(WebSocketTunnelFrame.MAX_PAYLOAD_BYTES, payload.length - offset);
            byte[] chunk = new byte[length];
            System.arraycopy(payload, offset, chunk, 0, length);
            offset += length;
            boolean last = offset == payload.length;
            int chunkOpcode = first ? opcode : WebSocketTunnelFrame.OPCODE_CONTINUATION;
            WebSocketTunnelFrame encoded = new WebSocketTunnelFrame(
                    chunkOpcode, finalFragment && last, first ? rsv : 0,
                    first ? closeCode : 0, chunk);
            StreamFlowController.get(controlCtx.channel()).send(
                    streamId, encoded.encode(), localCtx.channel(), localCtx::close);
            first = false;
        } while (offset < payload.length);
    }

    private static int opcode(WebSocketFrame frame) {
        if (frame instanceof TextWebSocketFrame) return WebSocketTunnelFrame.OPCODE_TEXT;
        if (frame instanceof BinaryWebSocketFrame) return WebSocketTunnelFrame.OPCODE_BINARY;
        if (frame instanceof ContinuationWebSocketFrame) return WebSocketTunnelFrame.OPCODE_CONTINUATION;
        if (frame instanceof CloseWebSocketFrame) return WebSocketTunnelFrame.OPCODE_CLOSE;
        if (frame instanceof PingWebSocketFrame) return WebSocketTunnelFrame.OPCODE_PING;
        if (frame instanceof PongWebSocketFrame) return WebSocketTunnelFrame.OPCODE_PONG;
        throw new IllegalArgumentException("unsupported WebSocket frame: " + frame.getClass().getSimpleName());
    }
}
