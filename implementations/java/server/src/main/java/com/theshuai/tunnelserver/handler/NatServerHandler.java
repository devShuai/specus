package com.theshuai.tunnelserver.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.tunnelserver.http.WebSocketStreamRegistry;
import com.theshuai.tunnelserver.http.WebSocketTunnelHandler;
import com.theshuai.tunnelserver.http.HttpStreamExchange;
import com.theshuai.tunnelserver.session.SessionUtil;
import com.theshuai.tunnelserver.attribute.ServerAttributes;
import com.theshuai.tunnelserver.config.NettyServerProperties;
import com.theshuai.tunnelserver.management.model.DisconnectReason;
import com.theshuai.tunnelserver.management.service.TrafficInspectionService;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.tunnelserver.server.RemotePortServerManager;
import com.theshuai.tunnelserver.server.TcpServer;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.DuplexChannel;
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
    // Pinned by client control connection: listenPort -> bound TcpServer.
    // Concurrent because the channel pipeline reads from arbitrary event loops.
    private final Map<Integer, TcpServer> remoteConnectionServerMap = new ConcurrentHashMap<>();

    // Public-internet channels for THIS client's tunnels, keyed by connection-local streamId.
    // Per-connection (not static) so DATA/DISCONNECTED routing is O(1) and a client can only
    // ever reach its own external channels. Concurrent because the accepted channels live on
    // their TcpServer's event loops while routing happens on the control connection's loop.
    private final Map<Integer, Channel> externalChannels = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> externalChannelPorts = new ConcurrentHashMap<>();
    private final Map<Integer, String> externalChannelIds = new ConcurrentHashMap<>();
    private final Map<Integer, HttpStreamExchange> httpStreams = new ConcurrentHashMap<>();

    private final TrafficUsageService trafficUsageService;
    private final TrafficInspectionService trafficInspectionService;
    private final RemotePortServerManager remotePortServerManager;
    private final NettyServerProperties nettyProperties;
    // WebSocket 隧道复用 NAT_MESSAGE 帧的 DATA/DISCONNECTED 路由：source="ws" 的流不进入
    // externalChannels，而是由 WebSocketStreamRegistry / WebSocketTunnelHandler 处理浏览器侧会话。
    private final WebSocketStreamRegistry webSocketStreamRegistry;
    private final WebSocketTunnelHandler webSocketTunnelHandler;
    private final AtomicInteger activeClientExternalChannels = new AtomicInteger();
    private final Map<Integer, AtomicInteger> portExternalChannelCounts = new ConcurrentHashMap<>();
    // Set during processRegister; null means the client has not registered any tunnel yet.
    private volatile String clientName;
    private volatile String tenantId = "default";
    // Per-connection flag. Each control connection gets its own handler instance, but we still
    // gate DATA/DISCONNECTED on successful REGISTER to reject out-of-order messages.
    private volatile boolean register = false;

    public NatServerHandler(TrafficUsageService trafficUsageService,
                            TrafficInspectionService trafficInspectionService,
                            RemotePortServerManager remotePortServerManager,
                            NettyServerProperties nettyProperties,
                            WebSocketStreamRegistry webSocketStreamRegistry,
                            WebSocketTunnelHandler webSocketTunnelHandler) {
        this.trafficUsageService = trafficUsageService;
        this.trafficInspectionService = trafficInspectionService;
        this.remotePortServerManager = remotePortServerManager;
        this.nettyProperties = nettyProperties;
        this.webSocketStreamRegistry = webSocketStreamRegistry;
        this.webSocketTunnelHandler = webSocketTunnelHandler;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof NatMessagePacket natMessagePacket)) {
            super.channelRead(ctx, msg);
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
            // WebSocket 流（source="ws" 或 channelId 命中 WS 注册表）不依赖 TCP REGISTER，
            // 单独放行；否则要求客户端已 REGISTER 至少一条 TCP 隧道。
            int streamId = natMessagePacket.getStreamId();
            if (httpStreams.containsKey(streamId)) {
                processHttpData(natMessagePacket);
            } else if (webSocketStreamRegistry.getByStreamId(streamId) != null) {
                processWsData(natMessagePacket);
            } else if (register) {
                processData(natMessagePacket);
            } else {
                log.warn("Dropping DATA before REGISTER on channel {}", ctx.channel().id().asLongText());
                DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
                ctx.close();
            }
        } else if (type == NatMessageType.FIN || type == NatMessageType.RST) {
            int streamId = natMessagePacket.getStreamId();
            if (httpStreams.containsKey(streamId)) {
                processHttpClosed(natMessagePacket);
            } else if (webSocketStreamRegistry.getByStreamId(streamId) != null) {
                processWsClosed(natMessagePacket);
            } else if (register) {
                processClosed(natMessagePacket);
            } else {
                log.warn("Dropping DISCONNECTED before REGISTER on channel {}", ctx.channel().id().asLongText());
                DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
                ctx.close();
            }
        } else if (type == NatMessageType.WINDOW_UPDATE) {
            processWindowUpdate(natMessagePacket);
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
        webSocketTunnelHandler.writeFrame(streamId, data);
        sendWindowUpdate(streamId, data.length);
    }

    public boolean openHttpStream(HttpStreamExchange exchange, Map<String, Object> metadata) {
        if (ctx == null || !ctx.channel().isActive()
                || httpStreams.putIfAbsent(exchange.streamId(), exchange) != null) {
            return false;
        }
        StreamFlowController.get(ctx.channel()).open(exchange.streamId(), null);
        NatMessagePacket open = new NatMessagePacket();
        open.setNatMessageType(NatMessageType.OPEN);
        open.setStreamId(exchange.streamId());
        open.setMetaData(metadata);
        ctx.writeAndFlush(open).addListener(result -> {
            if (!result.isSuccess()) {
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
                () -> httpStreams.remove(streamId));
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
        HttpStreamExchange exchange = httpStreams.remove(streamId);
        if (ctx != null) {
            StreamFlowController.get(ctx.channel()).reset(streamId, 8, reason);
        }
        if (exchange != null) {
            exchange.onReset(8, Map.of("reason", reason));
        }
    }

    public void unregisterHttpStream(int streamId) {
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
        }
    }

    private void processHttpClosed(NatMessagePacket packet) {
        HttpStreamExchange exchange = httpStreams.get(packet.getStreamId());
        if (exchange == null) {
            return;
        }
        if (packet.getNatMessageType() == NatMessageType.RST) {
            httpStreams.remove(packet.getStreamId());
            exchange.onReset(packet.getValue(), packet.getMetaData());
        } else {
            exchange.onFin(packet.getMetaData());
        }
    }

    private void processWsClosed(NatMessagePacket natMessagePacket) {
        webSocketTunnelHandler.closeFromClient(natMessagePacket.getStreamId());
    }

    private void processData(NatMessagePacket natMessagePacket) {
        byte[] data = natMessagePacket.getData();
        if (data == null) {
            log.warn("DATA frame with no payload from {}", clientName);
            return;
        }
        int streamId = natMessagePacket.getStreamId();
        Channel target = externalChannels.get(streamId);
        if (target == null) {
            return;
        }
        int listenPort = externalChannelPorts.getOrDefault(streamId, 0);
        String channelId = externalChannelIds.getOrDefault(streamId, Integer.toUnsignedString(streamId));
        trafficUsageService.recordTcpUpload(clientName, listenPort, data.length);
        // S1.1 endpoint 字符串走 target channel 上 RemoteTunnelHandler.channelActive 缓存的 attr，
        // 替代每帧 endpointAddress() 里的 instanceof + getHostAddress() 分配。
        ChannelAttributes.EndpointSnapshot localEp = ChannelAttributes.localEndpoint(target);
        ChannelAttributes.EndpointSnapshot remoteEp = ChannelAttributes.remoteEndpoint(target);
        trafficInspectionService.recordTcpFrame(clientName, listenPort, channelId,
                TrafficInspectionService.DIRECTION_CLIENT_TO_PUBLIC,
                localEp.address(),
                localEp.port(),
                remoteEp.address(),
                remoteEp.port(),
                data);
        target.writeAndFlush(data).addListener(future -> {
            if (!future.isSuccess()) {
                log.warn("write DATA to external channel {} failed [{}]",
                        ChannelAttributes.channelId(target), clientName, future.cause());
                target.close();
            } else {
                sendWindowUpdate(streamId, data.length);
                if ((natMessagePacket.getFlags() & NatMessagePacket.FLAG_END_STREAM) != 0) {
                    shutdownOutput(target);
                }
            }
        });
        if (!target.isWritable()) {
            pauseControlReads();
        }
    }

    private void processClosed(NatMessagePacket natMessagePacket) {
        Channel target = externalChannels.get(natMessagePacket.getStreamId());
        if (target != null) {
            if (natMessagePacket.getNatMessageType() == NatMessageType.RST) {
                StreamFlowController.get(ctx.channel()).remove(natMessagePacket.getStreamId());
                target.close();
            } else {
                shutdownOutput(target);
            }
        }
    }

    private static void shutdownOutput(Channel channel) {
        if (channel instanceof DuplexChannel duplexChannel) {
            duplexChannel.shutdownOutput();
        } else {
            channel.close();
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

    private void processRegister(NatMessagePacket natMessagePacket) {
        Map<String, Object> metaData = natMessagePacket.getMetaData();
        Integer port = asInt(metaData, "port");
        Integer tunnelPort = asInt(metaData, "tunnelPort");
        String tunnelAddress = asString(metaData, "tunnelAddress");
        String requestedClientName = asString(metaData, "clientName");

        Map<String, Object> result = new ConcurrentHashMap<>();
        result.put("port", port);

        if (port == null || tunnelPort == null || tunnelAddress == null || requestedClientName == null) {
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
        clientName = session.getClientName();
        String boundTenantId = ctx.channel().attr(ServerAttributes.TENANT_ID).get();
        tenantId = boundTenantId == null || boundTenantId.isBlank() ? "default" : boundTenantId;

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
                    int streamId = TunnelStreamIds.next();
                    try {
                        channel.pipeline().addLast(new ByteArrayDecoder(), new ByteArrayEncoder(),
                                new RemoteTunnelHandler(thisHandler, streamId, port, clientName, trafficUsageService,
                                        trafficInspectionService));
                        externalChannels.put(streamId, channel);
                        externalChannelPorts.put(streamId, port);
                        externalChannelIds.put(streamId, channelId);
                        syncExternalReadWithControl(channel);
                        channel.closeFuture().addListener(future -> {
                            if (externalChannels.remove(streamId) != null) {
                                externalChannelPorts.remove(streamId);
                                externalChannelIds.remove(streamId);
                                releaseExternalChannel(port);
                                updateControlAutoReadForExternalWritability();
                            }
                        });
                    } catch (RuntimeException e) {
                        externalChannels.remove(streamId);
                        externalChannelPorts.remove(streamId);
                        externalChannelIds.remove(streamId);
                        releaseExternalChannel(port);
                        throw e;
                    }
                }
            });

            remoteConnectionServerMap.put(port, remoteConnectionServer);
            register = true;
            result.put("success", true);
            log.info("register success, start server on port {} --> {}:{} [{}] ", port, tunnelAddress, tunnelPort, clientName);
        } catch (Exception e) {
            result.put("success", false);
            result.put("reason", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            log.error("REGISTER failed on port {} [{}]", port, clientName, e);
        }

        writeRegisterResult(result);

        if (!Boolean.TRUE.equals(result.get("success"))) {
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.REGISTER_FAILED);
            ctx.close();
        }
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
            if (register) {
                log.info("Stop server on port: {}", serverEntry.getKey());
            }
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
            webSocketTunnelHandler.onControlChannelInactive(clientName);
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
