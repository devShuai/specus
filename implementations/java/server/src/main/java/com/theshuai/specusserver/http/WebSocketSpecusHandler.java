package com.theshuai.specusserver.http;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.WebSocketSpecusFrame;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.handler.SpecusStreamIds;
import com.theshuai.specusserver.httpshare.HttpShareStreamRegistry;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.websocket.WsSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.BinaryMessage;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.PongMessage;
import org.springframework.web.socket.PingMessage;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.adapter.NativeWebSocketSession;
import org.springframework.web.socket.handler.AbstractWebSocketHandler;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * HTTP 直转通道的 WebSocket 隧道（浏览器侧）。
 *
 * <p>浏览器对 {@code /http/{clientName}/{route}/**} 发起 WebSocket 升级请求时，由
 * {@link WebSocketSpecusConfig} 把请求路由到本 handler。握手成功后，本 handler：
 * <ol>
 *   <li>分配连接内 {@code streamId}，向客户端控制连接发送 {@code OPEN} 帧
 *       （metaData 带 {@code source="ws"} + route/relativePath/rawQuery/headers/body）。</li>
 *   <li>把 {@link WebSocketSession} 注册进 {@link WebSocketStreamRegistry}。</li>
 *   <li>浏览器后续的 WebSocket 消息由容器分段交付（每段至多一个 SWS2 payload），编码为
 *       {@code SWS2} envelope 后写入 {@code DATA(streamId)}；单条消息至多 16 MiB，超出以 1009 关闭；
 *       等待 credit 的帧超过 1 MiB 时暂停读取浏览器。</li>
 *   <li>客户端从控制连接回送 {@code DATA(streamId)} 时，由 {@code NatServerHandler} 路由到
 *       {@link WebSocketStreamRegistry#get(String)}，再调用 {@link #writeFrame(String, byte[])}
 *       把载荷还原成 WS 帧写回浏览器。</li>
 *   <li>任一端断开 → {@code FIN(streamId)} 传播到对端；浏览器不带 CLOSE 断开（1006）时客户端收到
 *       {@code RST 31}。</li>
 * </ol>
 *
 * <p>{@code SWS2} 显式保留 opcode、FIN、RSV、close code/reason 和 payload 长度。
 */
@Component
@Slf4j
public class WebSocketSpecusHandler extends AbstractWebSocketHandler {
    /** WS 流在 CONNECTED metaData 里的 source 标记。 */
    static final String SOURCE_WS = "ws";
    /** A WebSocket message, in either direction and however fragmented, carries at most 16 MiB. */
    private static final int MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
    /**
     * The container hands each browser message over in parts of at most this many bytes (binary)
     * or characters (text): one part of a binary message fills one SWS2 frame. Tomcat allocates a
     * message buffer of its full limit for every session, so the 16 MiB message limit cannot be
     * that buffer; it is counted here instead.
     */
    static final int BROWSER_PART_LIMIT = WebSocketSpecusFrame.MAX_PAYLOAD_BYTES;
    /** Browser reads pause once this much SWS2 data waits on the stream, and resume at half of it. */
    static final long BROWSER_PAUSE_BYTES = StreamFlowController.INITIAL_WINDOW_BYTES;
    /** The RST code of a stream whose browser left without a CLOSE, as on the C and .NET servers. */
    static final long RST_BROWSER_GONE = 31;
    private static final String BROWSER_GONE_REASON = "WebSocket browser closed";
    private static final CloseStatus MESSAGE_TOO_BIG =
            CloseStatus.TOO_BIG_TO_PROCESS.withReason("WebSocket message too big");
    private static final long DEFAULT_CLOSE_CREDIT_TIMEOUT_MILLIS = 5_000;

    private final WebSocketStreamRegistry registry;
    private final long closeCreditTimeoutMillis;
    /** channelId → clientName，用于关闭时定位要发 DISCONNECTED 的控制连接。 */
    private final Map<String, String> channelClientNames = new ConcurrentHashMap<>();
    private final Map<String, Integer> channelStreamIds = new ConcurrentHashMap<>();
    /** channelId → the browser-to-device direction, present while the stream is attached. */
    private final Map<String, BrowserInbound> browserInbound = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> fragmentOpcodes = new ConcurrentHashMap<>();
    private final Map<Integer, ByteArrayOutputStream> fragmentPayloads = new ConcurrentHashMap<>();

    public WebSocketSpecusHandler(WebSocketStreamRegistry registry,
                                  @Value("${specus.http.websocket-close-timeout-ms:5000}")
                                  long closeCreditTimeoutMillis) {
        this.registry = registry;
        this.closeCreditTimeoutMillis = closeCreditTimeoutMillis > 0
                ? closeCreditTimeoutMillis : DEFAULT_CLOSE_CREDIT_TIMEOUT_MILLIS;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        String channelId = UUID.randomUUID().toString();
        int streamId = SpecusStreamIds.next();
        session.getAttributes().put(ATTR_CHANNEL_ID, channelId);
        session.getAttributes().put(ATTR_STREAM_ID, streamId);
        session.setTextMessageSizeLimit(BROWSER_PART_LIMIT);
        session.setBinaryMessageSizeLimit(BROWSER_PART_LIMIT);

        String clientName = (String) session.getAttributes().get(ATTR_CLIENT_NAME);
        String route = (String) session.getAttributes().get(ATTR_ROUTE);
        Channel controlChannel = SessionUtil.getDataChannel(clientName);
        if (controlChannel == null || !controlChannel.isActive()) {
            log.warn("[ws-specus][server] clientName={} rejected=client-offline channelId={}", clientName, channelId);
            releaseShareStream(session);
            session.close(CloseStatus.SERVER_ERROR.withReason("客户端不在线"));
            return;
        }

        registry.register(streamId, channelId, session, clientName);
        if (session.getAttributes().get(ATTR_SHARE_STREAM) instanceof HttpShareStreamRegistry.InFlight shareStream) {
            // A share that ends (revoked, expired, lapsed) closes this WebSocket with 1008.
            shareStream.attach(() -> terminate(channelId, CloseStatus.POLICY_VIOLATION, "HTTP share ended"));
        }
        markStreamOpened(controlChannel, streamId);
        StreamFlowController.get(controlChannel).open(streamId, null);
        channelClientNames.put(channelId, clientName);
        channelStreamIds.put(channelId, streamId);
        browserInbound.put(channelId, new BrowserInbound(tomcatSession(session)));

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

    /**
     * Messages arrive in parts of at most {@link #BROWSER_PART_LIMIT} instead of whole: the
     * container then never buffers a 16 MiB message, and each part is forwarded as it comes.
     */
    @Override
    public boolean supportsPartialMessages() {
        return true;
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        // A part never splits a character, so its UTF-8 bytes are exactly the browser's.
        forwardBrowserPart(session, WebSocketSpecusFrame.OPCODE_TEXT, message.isLast(), message.asBytes());
    }

    @Override
    protected void handleBinaryMessage(WebSocketSession session, BinaryMessage message) throws Exception {
        java.nio.ByteBuffer buf = message.getPayload();
        byte[] bytes = new byte[buf.remaining()];
        buf.get(bytes);
        forwardBrowserPart(session, WebSocketSpecusFrame.OPCODE_BINARY, message.isLast(), bytes);
    }

    @Override
    protected void handlePongMessage(WebSocketSession session, PongMessage message) throws Exception {
        ByteBuffer payload = message.getPayload();
        byte[] bytes = new byte[payload.remaining()];
        payload.get(bytes);
        BrowserInbound inbound = attachedInbound(session);
        if (inbound != null) {
            sendToDevice(session, inbound, WebSocketSpecusFrame.OPCODE_PONG, true, bytes);
        }
    }

    /**
     * Forwards one part of a browser text or binary message. Parts after the first continue the
     * message; a message past {@link #MAX_MESSAGE_BYTES} (UTF-8 bytes for text, as the other
     * servers count it) closes the browser with 1009 and ends the stream with the same CLOSE.
     */
    private void forwardBrowserPart(WebSocketSession session, int opcode, boolean last, byte[] payload) {
        BrowserInbound inbound = attachedInbound(session);
        if (inbound == null) {
            return;
        }
        if (payload.length > MAX_MESSAGE_BYTES - inbound.messageBytes) {
            String channelId = (String) session.getAttributes().get(ATTR_CHANNEL_ID);
            log.info("[ws-specus][browser->client] channelId={} refused=message-over-16MiB", channelId);
            detachBrowser(channelId, MESSAGE_TOO_BIG, true);
            return;
        }
        int frameOpcode = inbound.messageOpen ? WebSocketSpecusFrame.OPCODE_CONTINUATION : opcode;
        inbound.messageOpen = !last;
        inbound.messageBytes = last ? 0 : inbound.messageBytes + payload.length;
        sendToDevice(session, inbound, frameOpcode, last, payload);
    }

    /** The browser-to-device state of the session's stream, or null once the stream ended. */
    private BrowserInbound attachedInbound(WebSocketSession session) {
        String channelId = (String) session.getAttributes().get(ATTR_CHANNEL_ID);
        // Whatever the container still delivers after the stream ended goes nowhere.
        return channelId == null ? null : browserInbound.get(channelId);
    }

    private void sendToDevice(WebSocketSession session, BrowserInbound inbound, int opcode,
                              boolean finalFragment, byte[] payload) {
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
        StreamFlowController flow = StreamFlowController.get(controlChannel);
        int offset = 0;
        boolean first = true;
        do {
            int length = Math.min(WebSocketSpecusFrame.MAX_PAYLOAD_BYTES, payload.length - offset);
            byte[] chunk = new byte[length];
            System.arraycopy(payload, offset, chunk, 0, length);
            offset += length;
            boolean last = offset == payload.length;
            int chunkOpcode = first ? opcode : WebSocketSpecusFrame.OPCODE_CONTINUATION;
            byte[] framed = new WebSocketSpecusFrame(chunkOpcode, finalFragment && last, 0, 0, chunk).encode();
            inbound.queued(framed.length);
            flow.sendAtomicAsync(streamId, framed, null, () -> closeFromBrowser(channelId))
                    .whenComplete((ignored, error) -> inbound.sent(framed.length));
            first = false;
        } while (offset < payload.length);
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        String channelId = (String) session.getAttributes().get(ATTR_CHANNEL_ID);
        try {
            if (channelId != null) {
                log.info("[ws-specus][browser-closed] channelId={} status={}", channelId, status);
                detachBrowser(channelId, status, false);
            }
        } finally {
            // Whatever happened above, a share's slot must not stay taken by a closed WebSocket.
            releaseShareStream(session);
        }
    }

    /**
     * Tears a tunnel WebSocket down from the server side: the device gets a NAT RST for the stream
     * and the browser a close frame with {@code status}. Used when a temporary share ends.
     */
    public void terminate(String channelId, CloseStatus status, String resetReason) {
        endBrowserInbound(channelId);
        String clientName = channelClientNames.remove(channelId);
        Integer streamId = channelStreamIds.remove(channelId);
        Channel controlChannel = clientName == null || streamId == null
                ? null : SessionUtil.getDataChannel(clientName);
        WebSocketSession session = registry.remove(channelId);
        if (streamId != null) {
            clearFragmentState(streamId);
        }
        if (controlChannel != null && controlChannel.isActive()) {
            markStreamClosed(controlChannel, streamId);
            StreamFlowController.get(controlChannel).reset(streamId, 8, resetReason);
        }
        if (session != null && session.isOpen()) {
            try {
                synchronized (session) {
                    session.close(status);
                }
            } catch (Exception e) {
                log.debug("[ws-specus] terminate session {} failed: {}", channelId, e.toString());
            }
        }
    }

    private static void releaseShareStream(WebSocketSession session) {
        if (session.getAttributes().get(ATTR_SHARE_STREAM) instanceof HttpShareStreamRegistry.InFlight shareStream) {
            shareStream.release();
        }
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
        endBrowserInbound(channelId);
        channelClientNames.remove(channelId);
        channelStreamIds.remove(channelId);
        clearFragmentState(streamId);
        if (clientName != null) {
            Channel controlChannel = SessionUtil.getDataChannel(clientName);
            if (controlChannel != null) {
                markStreamClosed(controlChannel, streamId);
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

    /**
     * Ends the stream from the browser side. A close code the wire can carry goes to the device as
     * SWS2 CLOSE + FIN, a close without code (1005) as a CLOSE without code + FIN. A browser that
     * left without any CLOSE (1006, also Tomcat's report of a write timeout) or with another code
     * the wire cannot carry gets the stream reset with {@link #RST_BROWSER_GONE}, as the C and .NET
     * servers do: there is no close handshake to relay.
     */
    private void detachBrowser(String channelId, CloseStatus status, boolean closeSession) {
        endBrowserInbound(channelId);
        String clientName = channelClientNames.remove(channelId);
        Integer streamId = channelStreamIds.remove(channelId);
        Channel controlChannel = clientName == null || streamId == null
                ? null : SessionUtil.getDataChannel(clientName);
        if (controlChannel != null && controlChannel.isActive()) {
            markStreamClosed(controlChannel, streamId);
        }
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
        if (controlChannel == null || !controlChannel.isActive()) return;
        StreamFlowController flow = StreamFlowController.get(controlChannel);
        byte[] close = closeFrameFor(status);
        if (close == null) {
            log.info("[ws-specus][browser->client] channelId={} streamId={} reset=browser-gone status={}",
                    channelId, streamId, status);
            flow.reset(streamId, RST_BROWSER_GONE, BROWSER_GONE_REASON);
            return;
        }
        CompletableFuture<Void> sequence = flow.sendAtomicAsync(streamId, close, null, null)
                .thenCompose(ignored -> flow.finishAsync(streamId, null));
        var timeout = controlChannel.eventLoop().schedule(
                () -> sequence.completeExceptionally(
                        new TimeoutException("websocket close credit timeout")),
                closeCreditTimeoutMillis, TimeUnit.MILLISECONDS);
        sequence.whenComplete((ignored, error) -> {
            timeout.cancel(false);
            if (error == null) {
                return;
            }
            Throwable cause = unwrap(error);
            String resetReason = cause instanceof TimeoutException
                    ? "websocket close credit timeout"
                    : "websocket close send failed";
            flow.reset(streamId, 8, resetReason);
        });
    }

    /** The SWS2 CLOSE that relays {@code status}, or null when it has no close to relay. */
    private static byte[] closeFrameFor(CloseStatus status) {
        int code = status.getCode();
        if (code == CloseStatus.NO_STATUS_CODE.getCode()) {
            return new WebSocketSpecusFrame(WebSocketSpecusFrame.OPCODE_CLOSE, true, 0, 0, null).encode();
        }
        if (!WebSocketSpecusFrame.isSendableCloseCode(code)) {
            return null;
        }
        byte[] reason = status.getReason() == null
                ? new byte[0] : status.getReason().getBytes(StandardCharsets.UTF_8);
        if (reason.length > 123) {
            int length = 123;
            while (length > 0 && (reason[length] & 0xC0) == 0x80) {
                length--; // never cut a UTF-8 character in two
            }
            reason = java.util.Arrays.copyOf(reason, length);
        }
        return new WebSocketSpecusFrame(WebSocketSpecusFrame.OPCODE_CLOSE, true, 0, code, reason).encode();
    }

    /** The stream no longer takes browser data: reads resume so the container sees the browser leave. */
    private void endBrowserInbound(String channelId) {
        BrowserInbound inbound = browserInbound.remove(channelId);
        if (inbound != null) {
            inbound.close();
        }
    }

    /** Tomcat's own session behind {@code session}, whose reads can be suspended, or null. */
    private static WsSession tomcatSession(WebSocketSession session) {
        return session instanceof NativeWebSocketSession nativeSession
                ? nativeSession.getNativeSession(WsSession.class) : null;
    }

    /**
     * The browser-to-device direction of one tunnel WebSocket. The part's place in its message
     * decides its SWS2 opcode, and the message may carry at most {@link #MAX_MESSAGE_BYTES}. While
     * more than {@link #BROWSER_PAUSE_BYTES} of SWS2 frames wait on the stream (no device credit, or
     * a data connection that takes no more), the browser is not read, as control-protocol.md asks
     * of every upstream; otherwise a browser faster than the device fills the 4 MiB stream queue
     * and the stream is reset (RST 6) long before a 16 MiB message is through.
     */
    private static final class BrowserInbound {
        /** Suspends and resumes reading the browser; null on a container that cannot. */
        private final WsSession reads;
        // The message in progress: only the container thread delivering the browser's messages
        // touches these.
        private boolean messageOpen;
        private long messageBytes;
        // Shared with the data connection's event loop, which completes the queued frames.
        private long queuedBytes;
        private boolean paused;
        private boolean closed;

        private BrowserInbound(WsSession reads) {
            this.reads = reads;
        }

        synchronized void queued(int bytes) {
            queuedBytes += bytes;
            if (reads != null && !paused && !closed && queuedBytes >= BROWSER_PAUSE_BYTES) {
                paused = true;
                try {
                    reads.suspend();
                } catch (RuntimeException e) {
                    log.debug("[ws-specus] suspending browser reads failed: {}", e.toString());
                }
            }
        }

        /** A queued frame was written to the data connection, or dropped with its stream. */
        synchronized void sent(int bytes) {
            queuedBytes -= bytes;
            if (paused && queuedBytes <= BROWSER_PAUSE_BYTES / 2) {
                resume();
            }
        }

        synchronized void close() {
            closed = true;
            if (paused) {
                resume();
            }
        }

        private void resume() {
            paused = false;
            try {
                reads.resume();
            } catch (RuntimeException e) {
                log.debug("[ws-specus] resuming browser reads failed: {}", e.toString());
            }
        }
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while (current instanceof CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static void markStreamOpened(Channel controlChannel, int streamId) {
        NatServerHandler handler = controlChannel.pipeline().get(NatServerHandler.class);
        if (handler != null) {
            handler.markStreamOpened(streamId);
        }
    }

    private static void markStreamClosed(Channel controlChannel, int streamId) {
        NatServerHandler handler = controlChannel.pipeline().get(NatServerHandler.class);
        if (handler != null) {
            handler.markStreamClosed(streamId);
        }
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
    /** The in-flight slot of a WebSocket opened through a temporary share, if any. */
    static final String ATTR_SHARE_STREAM = "ws.shareStream";
}
