package com.theshuai.specusserver.http;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.WebSocketSpecusFrame;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.specusserver.handler.SpecusStreamIds;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.BinaryMessage;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.PongMessage;
import org.springframework.web.socket.PingMessage;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.AbstractWebSocketHandler;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
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
 * {@link WebSocketSpecusConfig} 把请求路由到本 handler。握手成功后，本 handler：
 * <ol>
 *   <li>分配连接内 {@code streamId}，向客户端控制连接发送 {@code OPEN} 帧
 *       （metaData 带 {@code source="ws"} + route/relativePath/rawQuery/headers/body）。</li>
 *   <li>把 {@link WebSocketSession} 注册进 {@link WebSocketStreamRegistry}。</li>
 *   <li>浏览器后续的 WebSocket 帧编码为 {@code SWS2} envelope 后写入 {@code DATA(streamId)}。</li>
 *   <li>客户端从控制连接回送 {@code DATA(streamId)} 时，由 {@code NatServerHandler} 路由到
 *       {@link WebSocketStreamRegistry#get(String)}，再调用 {@link #writeFrame(String, byte[])}
 *       把载荷还原成 WS 帧写回浏览器。</li>
 *   <li>任一端断开 → {@code FIN(streamId)} 传播到对端。</li>
 * </ol>
 *
 * <p>{@code SWS2} 显式保留 opcode、FIN、RSV、close code/reason 和 payload 长度。
 */
@Component
@Slf4j
public class WebSocketSpecusHandler extends AbstractWebSocketHandler {
    /** WS 流在 CONNECTED metaData 里的 source 标记。 */
    static final String SOURCE_WS = "ws";
    private static final int MAX_MESSAGE_BYTES = 16 * 1024 * 1024;

    private final WebSocketStreamRegistry registry;
    private final long timeoutMillis;
    /** channelId → clientName，用于关闭时定位要发 DISCONNECTED 的控制连接。 */
    private final Map<String, String> channelClientNames = new ConcurrentHashMap<>();
    private final Map<String, Integer> channelStreamIds = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> fragmentOpcodes = new ConcurrentHashMap<>();
    private final Map<Integer, ByteArrayOutputStream> fragmentPayloads = new ConcurrentHashMap<>();

    public WebSocketSpecusHandler(WebSocketStreamRegistry registry,
                                  @Value("${specus.http.timeout-ms:30000}") long timeoutMillis) {
        this.registry = registry;
        this.timeoutMillis = timeoutMillis;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        String channelId = UUID.randomUUID().toString();
        int streamId = SpecusStreamIds.next();
        session.getAttributes().put(ATTR_CHANNEL_ID, channelId);
        session.getAttributes().put(ATTR_STREAM_ID, streamId);

        String clientName = (String) session.getAttributes().get(ATTR_CLIENT_NAME);
        String route = (String) session.getAttributes().get(ATTR_ROUTE);
        Channel controlChannel = SessionUtil.getDataChannel(clientName);
        if (controlChannel == null || !controlChannel.isActive()) {
            log.warn("[ws-specus][server] clientName={} rejected=client-offline channelId={}", clientName, channelId);
            session.close(CloseStatus.SERVER_ERROR.withReason("客户端不在线"));
            return;
        }

        registry.register(streamId, channelId, session, clientName);
        StreamFlowController.get(controlChannel).open(streamId, null);
        channelClientNames.put(channelId, clientName);
        channelStreamIds.put(channelId, streamId);

        NatMessagePacket connected = new NatMessagePacket();
        connected.setNatMessageType(NatMessageType.OPEN);
        connected.setStreamId(streamId);
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
                log.warn("[ws-specus][server->client] channelId={} clientName={} write=connected-failed error={}",
                        channelId, clientName, future.cause() == null ? "unknown" : future.cause().toString());
                closeFromBrowser(channelId);
            } else {
                log.info("[ws-specus][server->client] channelId={} clientName={} route={} write=connected",
                        channelId, clientName, route);
            }
        });
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        handleAppFrame(session, WebSocketSpecusFrame.OPCODE_TEXT, message.isLast(), 0, 0, message.asBytes());
    }

    @Override
    protected void handleBinaryMessage(WebSocketSession session, BinaryMessage message) throws Exception {
        java.nio.ByteBuffer buf = message.getPayload();
        byte[] bytes = new byte[buf.remaining()];
        buf.get(bytes);
        handleAppFrame(session, WebSocketSpecusFrame.OPCODE_BINARY, message.isLast(), 0, 0, bytes);
    }

    @Override
    protected void handlePongMessage(WebSocketSession session, PongMessage message) throws Exception {
        ByteBuffer payload = message.getPayload();
        byte[] bytes = new byte[payload.remaining()];
        payload.get(bytes);
        handleAppFrame(session, WebSocketSpecusFrame.OPCODE_PONG, true, 0, 0, bytes);
    }

    private void handleAppFrame(WebSocketSession session, int opcode, boolean finalFragment,
                                int rsv, int closeCode, byte[] payload) {
        String channelId = (String) session.getAttributes().get(ATTR_CHANNEL_ID);
        Integer streamId = (Integer) session.getAttributes().get(ATTR_STREAM_ID);
        String clientName = (String) session.getAttributes().get(ATTR_CLIENT_NAME);
        if (channelId == null || streamId == null || clientName == null) {
            return;
        }
        Channel controlChannel = SessionUtil.getDataChannel(clientName);
        if (controlChannel == null || !controlChannel.isActive()) {
            closeFromBrowser(channelId);
            return;
        }
        int offset = 0;
        boolean first = true;
        do {
            int length = Math.min(WebSocketSpecusFrame.MAX_PAYLOAD_BYTES, payload.length - offset);
            byte[] chunk = new byte[length];
            System.arraycopy(payload, offset, chunk, 0, length);
            offset += length;
            boolean last = offset == payload.length;
            int chunkOpcode = first ? opcode : WebSocketSpecusFrame.OPCODE_CONTINUATION;
            byte[] framed = new WebSocketSpecusFrame(chunkOpcode, finalFragment && last,
                    first ? rsv : 0, first ? closeCode : 0, chunk).encode();
            StreamFlowController.get(controlChannel).sendAtomic(streamId, framed, null,
                    () -> closeFromBrowser(channelId));
            first = false;
        } while (offset < payload.length);
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        String channelId = (String) session.getAttributes().get(ATTR_CHANNEL_ID);
        if (channelId == null) {
            return;
        }
        log.info("[ws-specus][browser-closed] channelId={} status={}", channelId, status);
        detachBrowser(channelId, status, false);
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
        String channelId = (String) session.getAttributes().get(ATTR_CHANNEL_ID);
        log.warn("[ws-specus][transport-error] channelId={} error={}",
                channelId, exception == null ? "null" : exception.toString());
    }

    /**
     * 由 {@code NatServerHandler} 调用：客户端回送的 {@code DATA(streamId)} 还原成 WS 帧写回浏览器。
     */
    public void writeFrame(int streamId, byte[] payload) {
        String channelId = registry.channelIdOf(streamId);
        WebSocketSession session = registry.getByStreamId(streamId);
        if (session == null || !session.isOpen()) {
            return;
        }
        try {
            WebSocketSpecusFrame frame = WebSocketSpecusFrame.decode(payload);
            if (frame.rsv() != 0) {
                throw new IllegalArgumentException("RSV extensions are not available on the Spring endpoint");
            }
            byte[] framePayload = frame.payload();
            synchronized (session) {
                switch (frame.opcode()) {
                    case WebSocketSpecusFrame.OPCODE_TEXT -> {
                        if (beginMessage(streamId, frame)) {
                            session.sendMessage(new TextMessage(framePayload));
                        }
                    }
                    case WebSocketSpecusFrame.OPCODE_BINARY -> {
                        if (beginMessage(streamId, frame)) {
                            session.sendMessage(new BinaryMessage(framePayload));
                        }
                    }
                    case WebSocketSpecusFrame.OPCODE_CONTINUATION -> {
                        Integer original = fragmentOpcodes.get(streamId);
                        if (original == null) throw new IllegalArgumentException("orphan continuation frame");
                        ByteArrayOutputStream fragments = fragmentPayloads.get(streamId);
                        if (fragments == null) throw new IllegalArgumentException("missing fragmented message state");
                        int totalBytes = Math.addExact(fragments.size(), framePayload.length);
                        if (totalBytes > MAX_MESSAGE_BYTES) {
                            throw new IllegalArgumentException("WebSocket message exceeds 16 MiB");
                        }
                        fragments.writeBytes(framePayload);
                        if (frame.finalFragment()) {
                            byte[] messagePayload = fragments.toByteArray();
                            clearFragmentState(streamId);
                            if (original == WebSocketSpecusFrame.OPCODE_TEXT) {
                                session.sendMessage(new TextMessage(messagePayload));
                            } else {
                                session.sendMessage(new BinaryMessage(messagePayload));
                            }
                        }
                    }
                    case WebSocketSpecusFrame.OPCODE_PING ->
                            session.sendMessage(new PingMessage(ByteBuffer.wrap(framePayload)));
                    case WebSocketSpecusFrame.OPCODE_PONG ->
                            session.sendMessage(new PongMessage(ByteBuffer.wrap(framePayload)));
                    case WebSocketSpecusFrame.OPCODE_CLOSE -> session.close(new CloseStatus(
                            frame.closeCode() == 0 ? 1000 : frame.closeCode(),
                            new String(framePayload, StandardCharsets.UTF_8)));
                    default -> throw new IllegalArgumentException("unsupported SWS2 opcode");
                }
            }
        } catch (Exception e) {
            log.warn("[ws-specus][client->browser] channelId={} write=frame-failed error={}",
                    channelId, e.toString());
            closeFromClient(streamId);
        }
    }

    private boolean beginMessage(int streamId, WebSocketSpecusFrame frame) {
        if (fragmentOpcodes.containsKey(streamId)) {
            throw new IllegalArgumentException("new WebSocket message before fragmented message completed");
        }
        if (frame.finalFragment()) {
            return true;
        }
        byte[] payload = frame.payload();
        fragmentOpcodes.put(streamId, frame.opcode());
        ByteArrayOutputStream fragments = new ByteArrayOutputStream(payload.length);
        fragments.writeBytes(payload);
        fragmentPayloads.put(streamId, fragments);
        return false;
    }

    private void clearFragmentState(int streamId) {
        fragmentOpcodes.remove(streamId);
        fragmentPayloads.remove(streamId);
    }

    /**
     * 由 {@code NatServerHandler} 调用：客户端发回 {@code DISCONNECTED(channelId)}。
     * 只关浏览器会话，不再向客户端回送 DISCONNECTED。
     */
    public void closeFromClient(int streamId) {
        String channelId = registry.channelIdOf(streamId);
        String clientName = channelId == null ? null : registry.clientNameOf(channelId);
        WebSocketSession session = registry.removeByStreamId(streamId);
        if (channelId == null) {
            return;
        }
        channelClientNames.remove(channelId);
        channelStreamIds.remove(channelId);
        clearFragmentState(streamId);
        if (clientName != null) {
            Channel controlChannel = SessionUtil.getDataChannel(clientName);
            if (controlChannel != null) {
                StreamFlowController.get(controlChannel).remove(streamId);
            }
        }
        if (session != null && session.isOpen()) {
            try {
                session.close(CloseStatus.GOING_AWAY);
            } catch (Exception e) {
                log.debug("[ws-specus] close session {} from-client failed: {}", channelId, e.toString());
            }
        }
    }

    /**
     * 浏览器侧主动关闭或写失败：关闭会话并向客户端控制连接发 {@code DISCONNECTED}。
     */
    public void closeFromBrowser(String channelId) {
        detachBrowser(channelId, CloseStatus.SERVER_ERROR, true);
    }

    private void detachBrowser(String channelId, CloseStatus status, boolean closeSession) {
        String clientName = channelClientNames.remove(channelId);
        Integer streamId = channelStreamIds.remove(channelId);
        WebSocketSession session = registry.remove(channelId);
        if (streamId != null) clearFragmentState(streamId);
        if (closeSession && session != null && session.isOpen()) {
            try {
                session.close(status);
            } catch (Exception e) {
                log.debug("[ws-specus] close session {} from-browser failed: {}", channelId, e.toString());
            }
        }
        if (clientName == null || streamId == null) return;
        Channel controlChannel = SessionUtil.getDataChannel(clientName);
        if (controlChannel == null || !controlChannel.isActive()) return;
        byte[] reason = status.getReason() == null
                ? new byte[0] : status.getReason().getBytes(StandardCharsets.UTF_8);
        if (reason.length > 123) {
            reason = java.util.Arrays.copyOf(reason, 123);
        }
        byte[] close = new WebSocketSpecusFrame(WebSocketSpecusFrame.OPCODE_CLOSE, true, 0,
                status.getCode(), reason).encode();
        StreamFlowController flow = StreamFlowController.get(controlChannel);
        flow.sendAtomic(streamId, close, null, null);
        flow.finish(streamId);
    }

    /** 控制连接断开时由 {@code NatServerHandler.channelInactive} 调用：关闭所有挂起的浏览器会话。 */
    public void onControlChannelInactive(String clientName) {
        registry.closeAll(clientName);
    }

    static final String ATTR_CHANNEL_ID = "ws.channelId";
    static final String ATTR_STREAM_ID = "ws.streamId";
    static final String ATTR_CLIENT_NAME = "ws.clientName";
    static final String ATTR_ROUTE = "ws.route";
    static final String ATTR_RELATIVE_PATH = "ws.relativePath";
    static final String ATTR_RAW_QUERY = "ws.rawQuery";
    static final String ATTR_HEADERS = "ws.headers";
    static final String ATTR_BODY = "ws.body";
}
