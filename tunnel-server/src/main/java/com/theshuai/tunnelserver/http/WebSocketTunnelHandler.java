package com.theshuai.tunnelserver.http;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.tunnelserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.BinaryMessage;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.PongMessage;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.AbstractWebSocketHandler;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * HTTP 直转通道的 WebSocket 隧道（浏览器侧）。
 *
 * <p>浏览器对 {@code /http/{clientName}/{route}/**} 发起 WebSocket 升级请求时，由
 * {@link WebSocketTunnelConfig} 把请求路由到本 handler。握手成功后，本 handler：
 * <ol>
 *   <li>分配 {@code channelId = UUID}，向客户端控制连接发送 {@code CONNECTED} 帧
 *       （metaData 带 {@code source="ws"} + route/relativePath/rawQuery/headers/body）。</li>
 *   <li>把 {@link WebSocketSession} 注册进 {@link WebSocketStreamRegistry}。</li>
 *   <li>浏览器后续的 Text/Binary 帧 → {@code DATA(channelId, [1字节类型前缀] + 载荷)} 写控制连接。</li>
 *   <li>客户端从控制连接回送 {@code DATA(channelId)} 时，由 {@code NatServerHandler} 路由到
 *       {@link WebSocketStreamRegistry#get(String)}，再调用 {@link #writeFrame(String, byte[])}
 *       把载荷还原成 WS 帧写回浏览器。</li>
 *   <li>任一端断开 → {@code DISCONNECTED(channelId)} 传播到对端。</li>
 * </ol>
 *
 * <p>帧类型前缀约定（仅 WS 流，{@code data[0]}）：
 * <ul>
 *   <li>{@code 0x01} TextFrame</li>
 *   <li>{@code 0x02} BinaryFrame</li>
 * </ul>
 * Ping/Pong 由 Spring WebSocket 本地应答，不进 DATA 帧。
 */
@Component
@Slf4j
public class WebSocketTunnelHandler extends AbstractWebSocketHandler {
    /** WS 帧的 {@code data[0]} 类型前缀。 */
    static final byte FRAME_TEXT = 0x01;
    static final byte FRAME_BINARY = 0x02;

    /** WS 流在 CONNECTED metaData 里的 source 标记。 */
    static final String SOURCE_WS = "ws";

    private final WebSocketStreamRegistry registry;
    private final long timeoutMillis;
    /** channelId → clientName，用于关闭时定位要发 DISCONNECTED 的控制连接。 */
    private final Map<String, String> channelClientNames = new ConcurrentHashMap<>();

    public WebSocketTunnelHandler(WebSocketStreamRegistry registry,
                                  @Value("${tunnel.http.timeout-ms:30000}") long timeoutMillis) {
        this.registry = registry;
        this.timeoutMillis = timeoutMillis;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        String channelId = UUID.randomUUID().toString();
        session.getAttributes().put(ATTR_CHANNEL_ID, channelId);

        String clientName = (String) session.getAttributes().get(ATTR_CLIENT_NAME);
        String route = (String) session.getAttributes().get(ATTR_ROUTE);
        Channel controlChannel = SessionUtil.getChannel(clientName);
        if (controlChannel == null || !controlChannel.isActive()) {
            log.warn("[ws-tunnel][server] clientName={} rejected=client-offline channelId={}", clientName, channelId);
            session.close(CloseStatus.SERVER_ERROR.withReason("客户端不在线"));
            return;
        }

        registry.register(channelId, session, clientName);
        channelClientNames.put(channelId, clientName);

        NatMessagePacket connected = new NatMessagePacket();
        connected.setNatMessageType(NatMessageType.CONNECTED);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("source", SOURCE_WS);
        metaData.put("channelId", channelId);
        metaData.put("clientName", clientName);
        metaData.put("route", route);
        metaData.put("relativePath", session.getAttributes().get(ATTR_RELATIVE_PATH));
        metaData.put("rawQuery", session.getAttributes().get(ATTR_RAW_QUERY));
        metaData.put("headers", session.getAttributes().get(ATTR_HEADERS));
        metaData.put("body", session.getAttributes().get(ATTR_BODY));
        connected.setMetaData(metaData);
        controlChannel.writeAndFlush(connected).addListener(future -> {
            if (!future.isSuccess()) {
                log.warn("[ws-tunnel][server->client] channelId={} clientName={} write=connected-failed error={}",
                        channelId, clientName, future.cause() == null ? "unknown" : future.cause().toString());
                closeFromBrowser(channelId);
            } else {
                log.info("[ws-tunnel][server->client] channelId={} clientName={} route={} write=connected",
                        channelId, clientName, route);
            }
        });
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        handleAppFrame(session, FRAME_TEXT, message.asBytes());
    }

    @Override
    protected void handleBinaryMessage(WebSocketSession session, BinaryMessage message) throws Exception {
        java.nio.ByteBuffer buf = message.getPayload();
        byte[] bytes = new byte[buf.remaining()];
        buf.get(bytes);
        handleAppFrame(session, FRAME_BINARY, bytes);
    }

    @Override
    protected void handlePongMessage(WebSocketSession session, PongMessage message) throws Exception {
        // 本地处理 Pong，不透传
    }

    private void handleAppFrame(WebSocketSession session, byte frameType, byte[] payload) {
        String channelId = (String) session.getAttributes().get(ATTR_CHANNEL_ID);
        String clientName = (String) session.getAttributes().get(ATTR_CLIENT_NAME);
        if (channelId == null || clientName == null) {
            return;
        }
        Channel controlChannel = SessionUtil.getChannel(clientName);
        if (controlChannel == null || !controlChannel.isActive()) {
            closeFromBrowser(channelId);
            return;
        }
        byte[] framed = new byte[payload.length + 1];
        framed[0] = frameType;
        System.arraycopy(payload, 0, framed, 1, payload.length);

        NatMessagePacket data = new NatMessagePacket();
        data.setNatMessageType(NatMessageType.DATA);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("channelId", channelId);
        metaData.put("source", SOURCE_WS);
        data.setMetaData(metaData);
        data.setData(framed);
        controlChannel.writeAndFlush(data).addListener(future -> {
            if (!future.isSuccess()) {
                log.warn("[ws-tunnel][server->client] channelId={} write=data-failed error={}",
                        channelId, future.cause() == null ? "unknown" : future.cause().toString());
                closeFromBrowser(channelId);
            }
        });
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        String channelId = (String) session.getAttributes().get(ATTR_CHANNEL_ID);
        if (channelId == null) {
            return;
        }
        log.info("[ws-tunnel][browser-closed] channelId={} status={}", channelId, status);
        closeFromBrowser(channelId);
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
        String channelId = (String) session.getAttributes().get(ATTR_CHANNEL_ID);
        log.warn("[ws-tunnel][transport-error] channelId={} error={}",
                channelId, exception == null ? "null" : exception.toString());
    }

    /**
     * 由 {@code NatServerHandler} 调用：客户端回送的 {@code DATA(channelId)} 还原成 WS 帧写回浏览器。
     * {@code payload} 的 {@code data[0]} 是帧类型前缀，{@code data[1..]} 是 WS 帧载荷。
     */
    public void writeFrame(String channelId, byte[] payload) {
        WebSocketSession session = registry.get(channelId);
        if (session == null || !session.isOpen()) {
            return;
        }
        if (payload == null || payload.length == 0) {
            return;
        }
        byte frameType = payload[0];
        byte[] framePayload = new byte[payload.length - 1];
        System.arraycopy(payload, 1, framePayload, 0, framePayload.length);
        try {
            synchronized (session) {
                if (frameType == FRAME_TEXT) {
                    session.sendMessage(new TextMessage(new String(framePayload, StandardCharsets.UTF_8)));
                } else {
                    // BinaryFrame（含其它未知类型一律按 binary 透传，保证不丢字节）
                    session.sendMessage(new BinaryMessage(framePayload));
                }
            }
        } catch (Exception e) {
            log.warn("[ws-tunnel][client->browser] channelId={} write=frame-failed error={}",
                    channelId, e.toString());
            closeFromClient(channelId);
        }
    }

    /**
     * 由 {@code NatServerHandler} 调用：客户端发回 {@code DISCONNECTED(channelId)}。
     * 只关浏览器会话，不再向客户端回送 DISCONNECTED。
     */
    public void closeFromClient(String channelId) {
        WebSocketSession session = registry.remove(channelId);
        channelClientNames.remove(channelId);
        if (session != null && session.isOpen()) {
            try {
                session.close(CloseStatus.GOING_AWAY);
            } catch (Exception e) {
                log.debug("[ws-tunnel] close session {} from-client failed: {}", channelId, e.toString());
            }
        }
    }

    /**
     * 浏览器侧主动关闭或写失败：关闭会话并向客户端控制连接发 {@code DISCONNECTED}。
     */
    public void closeFromBrowser(String channelId) {
        String clientName = channelClientNames.remove(channelId);
        WebSocketSession session = registry.remove(channelId);
        if (session != null && session.isOpen()) {
            try {
                session.close(CloseStatus.GOING_AWAY);
            } catch (Exception e) {
                log.debug("[ws-tunnel] close session {} from-browser failed: {}", channelId, e.toString());
            }
        }
        if (clientName != null) {
            Channel controlChannel = SessionUtil.getChannel(clientName);
            if (controlChannel != null && controlChannel.isActive()) {
                NatMessagePacket disconnected = new NatMessagePacket();
                disconnected.setNatMessageType(NatMessageType.DISCONNECTED);
                Map<String, Object> metaData = new HashMap<>();
                metaData.put("channelId", channelId);
                metaData.put("source", SOURCE_WS);
                disconnected.setMetaData(metaData);
                controlChannel.writeAndFlush(disconnected);
            }
        }
    }

    /** 控制连接断开时由 {@code NatServerHandler.channelInactive} 调用：关闭所有挂起的浏览器会话。 */
    public void onControlChannelInactive(String clientName) {
        registry.closeAll(clientName);
    }

    static final String ATTR_CHANNEL_ID = "ws.channelId";
    static final String ATTR_CLIENT_NAME = "ws.clientName";
    static final String ATTR_ROUTE = "ws.route";
    static final String ATTR_RELATIVE_PATH = "ws.relativePath";
    static final String ATTR_RAW_QUERY = "ws.rawQuery";
    static final String ATTR_HEADERS = "ws.headers";
    static final String ATTR_BODY = "ws.body";
}
