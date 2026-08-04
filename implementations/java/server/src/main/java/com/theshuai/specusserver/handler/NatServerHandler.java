package com.theshuai.specusserver.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.handler.RecentStreamTombstones;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.http.WebSocketStreamRegistry;
import com.theshuai.specusserver.http.WebSocketSpecusHandler;
import com.theshuai.specusserver.http.HttpStreamExchange;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.management.model.DisconnectReason;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import com.theshuai.specusserver.server.RemotePortServerManager;
import com.theshuai.specusserver.server.TcpServer;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.bytes.ByteArrayDecoder;
import io.netty.handler.codec.bytes.ByteArrayEncoder;
import lombok.extern.slf4j.Slf4j;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class NatServerHandler extends NatCommonHandler {
    static final int RECENTLY_CLOSED_STREAM_LIMIT = 1024;
    // Pinned by client control connection: listenPort -> bound TcpServer.
    // Concurrent because the channel pipeline reads from arbitrary event loops.
    private final Map<Integer, TcpServer> remoteConnectionServerMap = new ConcurrentHashMap<>();

    // Public-internet channels for THIS client's specusMappings, keyed by connection-local streamId.
    // Per-connection (not static) so DATA/DISCONNECTED routing is O(1) and a client can only
    // ever reach its own external channels. Concurrent because the accepted channels live on
    // their TcpServer's event loops while routing happens on the control connection's loop.
    private final Map<Integer, Channel> externalChannels = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> externalChannelPorts = new ConcurrentHashMap<>();
    private final Map<Integer, String> externalChannelIds = new ConcurrentHashMap<>();
    private final Map<Integer, HttpStreamExchange> httpStreams = new ConcurrentHashMap<>();
    private final RecentStreamTombstones recentlyClosedStreams =
            new RecentStreamTombstones(RECENTLY_CLOSED_STREAM_LIMIT);

    private final TrafficUsageService trafficUsageService;
    private final TrafficInspectionService trafficInspectionService;
    private final RemotePortServerManager remotePortServerManager;
    private final NettyServerProperties nettyProperties;
    // WebSocket 隧道复用 NAT_MESSAGE 帧的 DATA/DISCONNECTED 路由：source="ws" 的流不进入
    // externalChannels，而是由 WebSocketStreamRegistry / WebSocketSpecusHandler 处理浏览器侧会话。
    private final WebSocketStreamRegistry webSocketStreamRegistry;
    private final WebSocketSpecusHandler webSocketSpecusHandler;
    private final AtomicInteger activeClientExternalChannels = new AtomicInteger();
    private final Map<Integer, AtomicInteger> portExternalChannelCounts = new ConcurrentHashMap<>();
    // Bound from the authenticated DATA-channel session on its first NAT frame or HTTP stream.
    private volatile String clientName;
    private volatile String tenantId = "default";

    public NatServerHandler(TrafficUsageService trafficUsageService,
                            TrafficInspectionService trafficInspectionService,
                            RemotePortServerManager remotePortServerManager,
                            NettyServerProperties nettyProperties,
                            WebSocketStreamRegistry webSocketStreamRegistry,
                            WebSocketSpecusHandler webSocketSpecusHandler) {
        this.trafficUsageService = trafficUsageService;
        this.trafficInspectionService = trafficInspectionService;
        this.remotePortServerManager = remotePortServerManager;
        this.nettyProperties = nettyProperties;
        this.webSocketStreamRegistry = webSocketStreamRegistry;
        this.webSocketSpecusHandler = webSocketSpecusHandler;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof NatMessagePacket natMessagePacket)) {
            super.channelRead(ctx, msg);
            return;
        }
        if (!bindAuthenticatedIdentity(ctx.channel())) {
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
            ctx.close();
            return;
        }
        NatMessageType type = natMessagePacket.getNatMessageType();
        if (type == NatMessageType.REGISTER) {
            processRegister(natMessagePacket);
        } else if (type == NatMessageType.UNREGISTER) {
            processUnregister(natMessagePacket);
        } else if (type == NatMessageType.OPEN) {
            processHttpResponseHead(natMessagePacket);
        } else if (type == NatMessageType.DATA) {
            int streamId = natMessagePacket.getStreamId();
            if (httpStreams.containsKey(streamId)) {
                processHttpData(natMessagePacket);
            } else if (webSocketStreamRegistry.getByStreamId(streamId) != null) {
                processWsData(natMessagePacket);
            } else {
                // An unclassified DATA frame must belong to an active ordinary TCP stream.
                // processData resets unknown IDs instead of silently accepting an illegal state.
                processData(natMessagePacket);
            }
        } else if (type == NatMessageType.FIN || type == NatMessageType.RST) {
            int streamId = natMessagePacket.getStreamId();
            if (httpStreams.containsKey(streamId)) {
                processHttpClosed(natMessagePacket);
            } else if (webSocketStreamRegistry.getByStreamId(streamId) != null) {
                processWsClosed(natMessagePacket);
            } else {
                processClosed(natMessagePacket);
            }
        } else if (type == NatMessageType.WINDOW_UPDATE) {
            processWindowUpdate(natMessagePacket);
        } else if (type == NatMessageType.KEEPALIVE) {
            // KEEPALIVE 是 NatCommonHandler 在 writer-idle 时主动发送的保活帧，静默接受即可。
            // 此前缺失该分支会导致入站 KEEPALIVE 落入 PROTOCOL_VIOLATION 断开连接（自相矛盾）。
        } else {
            log.warn("unexpected NAT stream type: {}", type);
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
            ctx.close();
        }
    }

    private void processWsData(NatMessagePacket natMessagePacket) {
        byte[] data = natMessagePacket.getData();
        if (data == null || data.length == 0) {
            log.warn("WS DATA frame with no payload from {}", clientName);
            return;
        }
        int streamId = natMessagePacket.getStreamId();
        // 流量记账：WS 流没有 listenPort，沿用 HTTP 直转的 route 维度，按 0 端口计入 TCP 计量。
        // 后续若要单独 WS 计量，可在这里扩展。
        trafficUsageService.recordTcpUpload(clientName, 0, data.length);
        webSocketSpecusHandler.writeFrame(streamId, data);
        sendWindowUpdate(streamId, data.length);
    }

    public boolean openHttpStream(HttpStreamExchange exchange, Map<String, Object> metadata) {
        if (ctx == null || !ctx.channel().isActive()
                || !bindAuthenticatedIdentity(ctx.channel())
                || httpStreams.putIfAbsent(exchange.streamId(), exchange) != null) {
            return false;
        }
        markStreamOpened(exchange.streamId());
        StreamFlowController.get(ctx.channel()).open(exchange.streamId(), null);
        NatMessagePacket open = new NatMessagePacket();
        open.setNatMessageType(NatMessageType.OPEN);
        open.setStreamId(exchange.streamId());
        open.setMetaData(metadata);
        ctx.writeAndFlush(open).addListener(result -> {
            if (!result.isSuccess()) {
                markStreamClosed(exchange.streamId());
                HttpStreamExchange removed = httpStreams.remove(exchange.streamId());
                if (removed != null) {
                    removed.onReset(7, Map.of("reason", "HTTP OPEN write failed"));
                }
            }
        });
        return true;
    }

    public CompletableFuture<Void> sendHttpData(int streamId, byte[] data) {
        if (ctx == null || !httpStreams.containsKey(streamId)) {
            return CompletableFuture.failedFuture(new IllegalStateException("HTTP stream is not active"));
        }
        return StreamFlowController.get(ctx.channel()).sendAsync(streamId, data, null,
                () -> {
                    markStreamClosed(streamId);
                    httpStreams.remove(streamId);
                });
    }

    public CompletableFuture<Void> finishHttpRequest(int streamId, List<String> trailers) {
        if (ctx == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("control channel is not active"));
        }
        Map<String, Object> metadata = trailers == null || trailers.isEmpty()
                ? null : Map.of("trailers", List.copyOf(trailers));
        return StreamFlowController.get(ctx.channel()).finishAsync(streamId, metadata);
    }

    public void consumeHttpResponseData(int streamId, int bytes) {
        sendWindowUpdate(streamId, bytes);
    }

    public void cancelHttpStream(int streamId, String reason) {
        markStreamClosed(streamId);
        HttpStreamExchange exchange = httpStreams.remove(streamId);
        if (ctx != null) {
            StreamFlowController.get(ctx.channel()).reset(streamId, 8, reason);
        }
        if (exchange != null) {
            exchange.onReset(8, Map.of("reason", reason));
        }
    }

    public void unregisterHttpStream(int streamId) {
        markStreamClosed(streamId);
        httpStreams.remove(streamId);
        if (ctx != null) {
            StreamFlowController.get(ctx.channel()).remove(streamId);
        }
    }

    private void processHttpResponseHead(NatMessagePacket packet) {
        HttpStreamExchange exchange = httpStreams.get(packet.getStreamId());
        if (exchange == null || !exchange.onResponseHead(packet.getMetaData())) {
            log.warn("Invalid HTTP response OPEN stream={} client={}",
                    Integer.toUnsignedString(packet.getStreamId()), clientName);
            cancelHttpStream(packet.getStreamId(), "invalid HTTP response headers");
        }
    }

    private void processHttpData(NatMessagePacket packet) {
        HttpStreamExchange exchange = httpStreams.get(packet.getStreamId());
        if (exchange == null || !exchange.onData(packet.getData())) {
            cancelHttpStream(packet.getStreamId(), "HTTP response queue exceeded");
            return;
        }
        if ((packet.getFlags() & NatMessagePacket.FLAG_END_STREAM) != 0
                && !exchange.onFin(packet.getMetaData())) {
            cancelHttpStream(packet.getStreamId(), "duplicate HTTP FIN");
        }
    }

    private void processHttpClosed(NatMessagePacket packet) {
        HttpStreamExchange exchange = httpStreams.get(packet.getStreamId());
        if (exchange == null) {
            return;
        }
        if (packet.getNatMessageType() == NatMessageType.RST) {
            httpStreams.remove(packet.getStreamId());
            markStreamClosed(packet.getStreamId());
            exchange.onReset(packet.getValue(), packet.getMetaData());
        } else if (!exchange.onFin(packet.getMetaData())) {
            cancelHttpStream(packet.getStreamId(), "duplicate HTTP FIN");
        }
    }

    private void processWsClosed(NatMessagePacket natMessagePacket) {
        markStreamClosed(natMessagePacket.getStreamId());
        webSocketSpecusHandler.closeFromClient(natMessagePacket.getStreamId());
    }

    private void processData(NatMessagePacket natMessagePacket) {
        byte[] data = natMessagePacket.getData();
        int streamId = natMessagePacket.getStreamId();
        if (data == null) {
            log.warn("DATA frame with no payload from {}", clientName);
            resetTcpStream(streamId, 7, "TCP DATA frame has no payload");
            return;
        }
        Channel target = externalChannels.get(streamId);
        if (target == null) {
            resetTcpStream(streamId, 7, "DATA for unknown TCP stream");
            return;
        }
        RemoteSpecusHandler handler = target.pipeline().get(RemoteSpecusHandler.class);
        if (handler == null) {
            log.warn("TCP stream {} has no RemoteSpecusHandler [{}]",
                    Integer.toUnsignedString(streamId), clientName);
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
            ctx.close();
            return;
        }
        handler.writeFromClient(data,
                (natMessagePacket.getFlags() & NatMessagePacket.FLAG_END_STREAM) != 0);
    }

    private void processClosed(NatMessagePacket natMessagePacket) {
        int streamId = natMessagePacket.getStreamId();
        Channel target = externalChannels.get(streamId);
        if (target == null) {
            if (natMessagePacket.getNatMessageType() == NatMessageType.RST) {
                if (recentlyClosedStreams.contains(streamId)) {
                    return;
                }
                log.warn("RST for never-opened stream {} from {}",
                        Integer.toUnsignedString(streamId), clientName);
                DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
                ctx.close();
                return;
            }
            resetTcpStream(streamId, 7, "FIN for unknown TCP stream");
            return;
        }
        RemoteSpecusHandler handler = target.pipeline().get(RemoteSpecusHandler.class);
        if (handler == null) {
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
            ctx.close();
            return;
        }
        if (natMessagePacket.getNatMessageType() == NatMessageType.RST) {
            markStreamClosed(streamId);
            handler.receiveClientReset();
        } else {
            handler.receiveClientFin();
        }
    }

    private void processWindowUpdate(NatMessagePacket packet) {
        StreamFlowController.get(ctx.channel()).onWindowUpdate(packet.getStreamId(), packet.getValue());
    }

    private void sendWindowUpdate(int streamId, int credit) {
        if (ctx == null || credit <= 0) {
            return;
        }
        NatMessagePacket update = new NatMessagePacket();
        update.setNatMessageType(NatMessageType.WINDOW_UPDATE);
        update.setStreamId(streamId);
        update.setValue(Integer.toUnsignedLong(credit));
        ctx.writeAndFlush(update);
    }

    void sendTcpWindowUpdate(int streamId, int credit) {
        sendWindowUpdate(streamId, credit);
    }

    void resetTcpStream(int streamId, long errorCode, String reason) {
        if (ctx == null) {
            return;
        }
        markStreamClosed(streamId);
        if (ctx.channel().isActive()) {
            StreamFlowController.get(ctx.channel()).reset(streamId, errorCode, reason);
        } else {
            StreamFlowController.get(ctx.channel()).remove(streamId);
        }
    }

    void abortTcpStream(int streamId) {
        markStreamClosed(streamId);
        if (ctx != null) {
            StreamFlowController.get(ctx.channel()).remove(streamId);
        }
    }

    void pauseTcpControlReads() {
        pauseControlReads();
    }

    private void processUnregister(NatMessagePacket natMessagePacket) {
        Integer port = asInt(natMessagePacket.getMetaData(), "port");
        if (port == null) {
            return;
        }
        TcpServer server = remoteConnectionServerMap.remove(port);
        if (server != null) {
            server.close();
            log.info("Stop server on port: {} [{}]", port, clientName);
        }
    }

    private boolean bindAuthenticatedIdentity(Channel channel) {
        if (clientName != null) {
            return true;
        }
        Session session = SessionUtil.getSession(channel);
        if (session == null) {
            return false;
        }
        clientName = session.getClientName();
        String boundTenantId = channel.attr(ServerAttributes.TENANT_ID).get();
        tenantId = boundTenantId == null || boundTenantId.isBlank() ? "default" : boundTenantId;
        return true;
    }

    private void processRegister(NatMessagePacket natMessagePacket) {
        Map<String, Object> metaData = natMessagePacket.getMetaData();
        Integer port = asInt(metaData, "port");
        Integer specusPort = asInt(metaData, "specusPort");
        String specusAddress = asString(metaData, "specusAddress");
        String requestedClientName = asString(metaData, "clientName");

        Map<String, Object> result = new ConcurrentHashMap<>();
        if (port != null) {
            result.put("port", port);
        }

        if (port == null || specusPort == null || specusAddress == null || requestedClientName == null) {
            result.put("success", false);
            result.put("reason", "missing required metadata");
            writeRegisterResult(result);
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.REGISTER_FAILED);
            ctx.close();
            return;
        }

        Session session = SessionUtil.getSession(ctx.channel());
        if (session == null || !session.getClientName().equals(requestedClientName)) {
            // Claiming a different client name than the auth session — kick.
            log.warn("REGISTER clientName mismatch: session={}, claimed={}", session, requestedClientName);
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
            ctx.close();
            return;
        }
        bindAuthenticatedIdentity(ctx.channel());

        if (remoteConnectionServerMap.containsKey(port)) {
            // Port already in use on this server. Reject instead of silently reporting success.
            result.put("success", false);
            result.put("reason", "port " + port + " already in use");
            writeRegisterResult(result);
            log.warn("REGISTER rejected, port {} already in use [{}]", port, clientName);
            return;
        }

        try {
            NatServerHandler thisHandler = this;
            TcpServer remoteConnectionServer = remotePortServerManager.bind(port, new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel channel) {
                    if (!tryAcquireExternalChannel(port)) {
                        log.warn("Reject external connection on port {} [{}], activeClient={}, activeGlobal={}",
                                port, clientName, activeClientExternalChannels.get(),
                                remotePortServerManager.activeExternalConnections());
                        channel.close();
                        return;
                    }
                    String channelId = channel.id().asLongText();
                    int streamId = SpecusStreamIds.next();
                    try {
                        channel.pipeline().addLast(new ByteArrayDecoder(), new ByteArrayEncoder(),
                                new RemoteSpecusHandler(thisHandler, streamId, port, clientName, trafficUsageService,
                                        trafficInspectionService));
                        externalChannels.put(streamId, channel);
                        markStreamOpened(streamId);
                        externalChannelPorts.put(streamId, port);
                        externalChannelIds.put(streamId, channelId);
                        syncExternalReadWithControl(channel);
                        channel.closeFuture().addListener(future -> {
                            markStreamClosed(streamId);
                            if (externalChannels.remove(streamId) != null) {
                                externalChannelPorts.remove(streamId);
                                externalChannelIds.remove(streamId);
                                releaseExternalChannel(port);
                                updateControlAutoReadForExternalWritability();
                            }
                        });
                    } catch (RuntimeException e) {
                        markStreamClosed(streamId);
                        externalChannels.remove(streamId);
                        externalChannelPorts.remove(streamId);
                        externalChannelIds.remove(streamId);
                        releaseExternalChannel(port);
                        throw e;
                    }
                }
            });

            remoteConnectionServerMap.put(port, remoteConnectionServer);
            result.put("success", true);
            log.info("register success, start server on port {} --> {}:{} [{}] ", port, specusAddress, specusPort, clientName);
        } catch (Exception e) {
            result.put("success", false);
            result.put("reason", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            log.error("REGISTER failed on port {} [{}]", port, clientName, e);
        }

        writeRegisterResult(result);
    }

    private void writeRegisterResult(Map<String, Object> metaData) {
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.REGISTER_RESULT);
        message.setMetaData(metaData);
        ctx.writeAndFlush(message);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("{} inactive close", ctx.channel().id().asLongText());
        for (Map.Entry<Integer, TcpServer> serverEntry : remoteConnectionServerMap.entrySet()) {
            serverEntry.getValue().close();
            log.info("Stop server on port: {}", serverEntry.getKey());
        }
        remoteConnectionServerMap.clear();
        externalChannels.values().forEach(Channel::close);
        httpStreams.values().forEach(exchange ->
                exchange.onReset(9, Map.of("reason", "control channel closed")));
        httpStreams.clear();
        StreamFlowController.get(ctx.channel()).closeAll();
        externalChannelPorts.clear();
        externalChannelIds.clear();
        // 客户端控制连接断开：关闭所有挂起的浏览器 WS 会话，避免浏览器侧永久挂起
        if (clientName != null) {
            webSocketSpecusHandler.onControlChannelInactive(clientName);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        log.info("{} exception happen", ctx.channel().id().asLongText());
        // 异常如果首先从 NatServerHandler 内部抛出，inbound 事件会向 tail 传，
        // 不会反向到 ManagedLoginRequestHandler.exceptionCaught；这里兜底打一份标。
        DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.IO_ERROR);
        super.exceptionCaught(ctx, cause);
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        remoteConnectionServerMap.values().forEach(TcpServer::close);
        super.channelUnregistered(ctx);
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        StreamFlowController.get(ctx.channel()).onControlWritabilityChanged();
        updateExternalAutoReadForControlWritability();
        updateControlAutoReadForExternalWritability();
        super.channelWritabilityChanged(ctx);
    }

    public void updateControlAutoReadForExternalWritability() {
        if (ctx != null) {
            ChannelBackpressure.setAutoRead(ctx.channel(),
                    ctx.channel().isWritable() && ChannelBackpressure.allWritable(externalChannels.values()));
        }
    }

    private void pauseControlReads() {
        if (ctx != null) {
            ChannelBackpressure.setAutoRead(ctx.channel(), false);
        }
    }

    private void updateExternalAutoReadForControlWritability() {
        if (ctx == null) {
            return;
        }
        boolean controlWritable = ctx.channel().isWritable();
        externalChannels.values().forEach(channel -> ChannelBackpressure.setAutoRead(channel, controlWritable));
    }

    private void syncExternalReadWithControl(Channel channel) {
        if (ctx != null) {
            ChannelBackpressure.setAutoRead(channel, ctx.channel().isWritable());
        }
    }

    private boolean tryAcquireExternalChannel(int port) {
        if (!remotePortServerManager.tryAcquireExternalConnection(tenantId)) {
            return false;
        }
        if (!tryIncrement(activeClientExternalChannels, nettyProperties.getMaxExternalConnectionsPerClient())) {
            remotePortServerManager.releaseExternalConnection(tenantId);
            remotePortServerManager.recordRejectedExternalConnection(tenantId);
            return false;
        }
        AtomicInteger portCounter = portExternalChannelCounts.computeIfAbsent(port, key -> new AtomicInteger());
        if (!tryIncrement(portCounter, nettyProperties.getMaxExternalConnectionsPerPort())) {
            decrement(activeClientExternalChannels);
            remotePortServerManager.releaseExternalConnection(tenantId);
            remotePortServerManager.recordRejectedExternalConnection(tenantId);
            return false;
        }
        return true;
    }

    private void releaseExternalChannel(int port) {
        AtomicInteger portCounter = portExternalChannelCounts.get(port);
        if (portCounter != null && decrement(portCounter) == 0) {
            portExternalChannelCounts.remove(port, portCounter);
        }
        decrement(activeClientExternalChannels);
        remotePortServerManager.releaseExternalConnection(tenantId);
    }

    private static boolean tryIncrement(AtomicInteger counter, int max) {
        if (max <= 0) {
            counter.incrementAndGet();
            return true;
        }
        while (true) {
            int current = counter.get();
            if (current >= max) {
                return false;
            }
            if (counter.compareAndSet(current, current + 1)) {
                return true;
            }
        }
    }

    private static int decrement(AtomicInteger counter) {
        return counter.updateAndGet(current -> current > 0 ? current - 1 : 0);
    }

    /** Register a stream created outside this handler, such as a tunneled WebSocket. */
    public void markStreamOpened(int streamId) {
        recentlyClosedStreams.remove(streamId);
    }

    /** Register a completed stream so a late peer RST remains idempotent. */
    public void markStreamClosed(int streamId) {
        recentlyClosedStreams.add(streamId);
    }

    private static String asString(Map<String, Object> meta, String key) {
        if (meta == null) {
            return null;
        }
        Object v = meta.get(key);
        return v == null ? null : v.toString();
    }

    private static Integer asInt(Map<String, Object> meta, String key) {
        if (meta == null) {
            return null;
        }
        Object v = meta.get(key);
        if (v instanceof Number n) {
            return n.intValue();
        }
        if (v instanceof String s) {
            try {
                return Integer.parseInt(s);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static String endpointAddress(SocketAddress address) {
        if (address instanceof InetSocketAddress socketAddress) {
            return socketAddress.getAddress() == null
                    ? socketAddress.getHostString()
                    : socketAddress.getAddress().getHostAddress();
        }
        return address == null ? null : address.toString();
    }

    private static Integer endpointPort(SocketAddress address) {
        return address instanceof InetSocketAddress socketAddress ? socketAddress.getPort() : null;
    }
}
