package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;

import java.util.HashMap;
import java.util.Map;

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
    /** WS 帧的 {@code data[0]} 类型前缀，与服务端一致。 */
    static final byte FRAME_TEXT = 0x01;
    static final byte FRAME_BINARY = 0x02;

    private final NatClientHandler tunnelHandler;
    private final String remoteChannelId;
    private volatile boolean registered;

    public WsLocalTunnelHandler(NatClientHandler tunnelHandler, String remoteChannelId) {
        this.tunnelHandler = tunnelHandler;
        this.remoteChannelId = remoteChannelId;
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt == WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE) {
            registered = tunnelHandler.registerWsLocalChannel(remoteChannelId, ctx);
            if (registered) {
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
        byte frameType;
        if (frame instanceof TextWebSocketFrame) {
            frameType = FRAME_TEXT;
        } else if (frame instanceof BinaryWebSocketFrame) {
            frameType = FRAME_BINARY;
        } else {
            // Ping/Pong/Close 由本地 WS 栈处理，不透传
            return;
        }
        ByteBuf payload = frame.content();
        byte[] data = new byte[payload.readableBytes() + 1];
        data[0] = frameType;
        payload.getBytes(payload.readerIndex(), data, 1, payload.readableBytes());

        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DATA);
        message.setData(data);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", remoteChannelId);
        metaData.put("source", "ws");
        message.setMetaData(metaData);
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
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        // 只有握手成功注册过的流才需要通知服务端 DISCONNECTED；握手未完成就断开时，
        // NatClientHandler.processWsConnected 已经发过 DISCONNECTED。
        if (registered) {
            tunnelHandler.removeWsLocalHandler(remoteChannelId, this);
            NatMessagePacket message = new NatMessagePacket();
            message.setNatMessageType(NatMessageType.DISCONNECTED);
            Map<String, Object> metaData = new HashMap<>();
            metaData.put("channelId", remoteChannelId);
            metaData.put("source", "ws");
            message.setMetaData(metaData);
            ChannelHandlerContext controlCtx = tunnelHandler.getCtx();
            if (controlCtx != null && controlCtx.channel().isActive()) {
                controlCtx.writeAndFlush(message);
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
        if (payload == null || payload.length == 0) {
            return;
        }
        byte frameType = payload[0];
        ByteBuf buf = localCtx.alloc().buffer(payload.length - 1);
        buf.writeBytes(payload, 1, payload.length - 1);
        WebSocketFrame frame;
        if (frameType == FRAME_TEXT) {
            frame = new TextWebSocketFrame(buf);
        } else {
            frame = new BinaryWebSocketFrame(buf);
        }
        localCtx.writeAndFlush(frame).addListener(future -> {
            if (!future.isSuccess()) {
                localCtx.close();
            }
        });
    }
}
