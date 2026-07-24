package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.tunnelclient.bean.HttpTunnelConfig;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.bean.TunnelConfig;
import com.theshuai.tunnelclient.client.TcpConnection;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.DuplexChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshaker;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshakerFactory;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler;
import io.netty.handler.codec.http.websocketx.WebSocketVersion;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.handler.codec.bytes.ByteArrayDecoder;
import io.netty.handler.codec.bytes.ByteArrayEncoder;
import io.netty.util.concurrent.GlobalEventExecutor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Slf4j
public class NatClientHandler extends NatCommonHandler {

    private String remoteHost;

    private Map<Integer, TunnelConfig> tunnelConfigMap = new HashMap<>();

    /**
     * HTTP 路由快照（route → targetBaseUrl）。WS 隧道 CONNECTED 帧到达时按 route 查本地
     * {@code ws://} 或 HTTP 目标。volatile 整体替换，供强制 NAT stream v2 转发使用。
     */
    private volatile Map<String, String> httpRoutes = Map.of();

    private final ConcurrentHashMap<Integer, LocalTunnelHandler> channelHandlerMap = new ConcurrentHashMap<>();
    /** WS 隧道流的本地 Channel，key = 服务端分配的 streamId。 */
    private final ConcurrentHashMap<Integer, ChannelHandlerContext> wsLocalChannels = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Integer, HttpStreamForwarder> httpStreams = new ConcurrentHashMap<>();
    private ChannelGroup channelGroup = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    private final Set<Integer> registeredPorts = new HashSet<>();
    private final String clientName;
    private final TcpConnection localConnection;
    /** 本地 WS 连接用的独立 EventLoopGroup（复用 {@link TcpConnection} 的 group 也可，这里独立以便清晰）。 */
    private EventLoopGroup wsWorkerGroup;
    public NatClientHandler(TunnelBean tunnelBean) {
        this(tunnelBean, new TcpConnection());
    }

    public NatClientHandler(TunnelBean tunnelBean, TcpConnection localConnection) {
        this.remoteHost = tunnelBean.getRemoteAddress();
        this.clientName = tunnelBean.getClientName();
        this.localConnection = localConnection;
        if (tunnelBean.getTunnelConfigList() != null) {
            for (TunnelConfig tunnelConfig : tunnelBean.getTunnelConfigList()) {
                tunnelConfigMap.put(tunnelConfig.getPort(), tunnelConfig);
            }
        }
        this.httpRoutes = toHttpRouteMap(tunnelBean.getHttpTunnelConfigList());
    }

    private static Map<String, String> toHttpRouteMap(List<HttpTunnelConfig> configs) {
        if (configs == null || configs.isEmpty()) {
            return Map.of();
        }
        Map<String, String> map = new HashMap<>();
        for (HttpTunnelConfig c : configs) {
            if (c != null && c.getRoute() != null && !c.getRoute().isBlank()) {
                map.put(c.getRoute(), c.getTargetBaseUrl() == null ? "" : c.getTargetBaseUrl());
            }
        }
        return Map.copyOf(map);
    }

    /**
     * 服务端通过 NAT_CONTROL 下发新 HTTP 路由全集时，由 {@link MessageResponseHandler} 调用，
     * 该快照同时用于 HTTP 和 WebSocket 路由，空列表表示清空全部路由。
     */
    public void applyHttpRoutes(List<HttpTunnelConfig> next) {
        this.httpRoutes = toHttpRouteMap(next);
        log.info("[ws-tunnel][client] httpRoutes updated: {} entries", httpRoutes.size());
    }

    Map<String, String> getCurrentHttpRoutes() {
        return httpRoutes;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        super.handlerAdded(ctx);
        this.ctx = ctx;
        if (!StringUtils.hasText(remoteHost)) {
            remoteHost = String.valueOf(ctx.channel().remoteAddress());
        }
        // The control channel is already active when this handler is added after a
        // NAT_CONTROL push, so channelActive will not fire. Register the tunnels here.
        if (ctx.channel().isActive()) {
            registerTunnels(ctx);
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        registerTunnels(ctx);
        super.channelActive(ctx);
    }

    private synchronized void registerTunnels(ChannelHandlerContext ctx) {
        for (Map.Entry<Integer, TunnelConfig> tunnelConfigEntry : tunnelConfigMap.entrySet()) {
            Integer port = tunnelConfigEntry.getKey();
            if (!registeredPorts.add(port)) {
                continue;
            }
            NatMessagePacket message = new NatMessagePacket();
            message.setNatMessageType(NatMessageType.REGISTER);
            Map<String, Object> metaData = new HashMap<>();
            metaData.put("port", port);
            metaData.put("tunnelAddress", tunnelConfigEntry.getValue().getTunnelAddress());
            metaData.put("tunnelPort", tunnelConfigEntry.getValue().getTunnelPort());
            metaData.put("clientName", clientName);
            message.setMetaData(metaData);
            ctx.writeAndFlush(message);
        }
    }

    public synchronized void applyConfig(TunnelBean tunnelBean) {
        if (StringUtils.hasText(tunnelBean.getRemoteAddress())) {
            remoteHost = tunnelBean.getRemoteAddress();
        }
        Map<Integer, TunnelConfig> desired = new HashMap<>();
        if (tunnelBean.getTunnelConfigList() != null) {
            for (TunnelConfig tunnelConfig : tunnelBean.getTunnelConfigList()) {
                desired.put(tunnelConfig.getPort(), tunnelConfig);
            }
        }
        for (Integer port : new HashSet<>(registeredPorts)) {
            if (!desired.containsKey(port)) {
                NatMessagePacket message = new NatMessagePacket();
                message.setNatMessageType(NatMessageType.UNREGISTER);
                Map<String, Object> metaData = new HashMap<>();
                metaData.put("port", port);
                message.setMetaData(metaData);
                ctx.writeAndFlush(message);
                registeredPorts.remove(port);
            }
        }
        tunnelConfigMap = desired;
        registerTunnels(ctx);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        StreamFlowController.get(ctx.channel()).closeAll();
        channelGroup.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
        channelHandlerMap.clear();
        wsLocalChannels.values().forEach(ch -> ch.close().awaitUninterruptibly(5, TimeUnit.SECONDS));
        wsLocalChannels.clear();
        httpStreams.values().forEach(stream -> stream.cancel("control channel closed"));
        httpStreams.clear();
        localConnection.close();
        if (wsWorkerGroup != null) {
            EventLoopGroup toShutdown = wsWorkerGroup;
            wsWorkerGroup = null;
            shutdownGroup(toShutdown);
        }
        // 重连时新 handler 实例会重置；同一实例（NAT_CONTROL 复用）也允许再次上报
        log.info("Loss connection to Nat server... Please restart!");
    }

    private void shutdownGroup(EventLoopGroup group) {
        if (group == null) {
            return;
        }
        group.shutdownGracefully(0, 5, TimeUnit.SECONDS)
                .awaitUninterruptibly(10, TimeUnit.SECONDS);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof NatMessagePacket natMessagePacket)) {
            ctx.fireChannelRead(msg);
            return;
        }
        switch (natMessagePacket.getNatMessageType()) {
            case REGISTER_RESULT:
                processRegisterResult(natMessagePacket);
                break;
            case OPEN:
                processOpen(natMessagePacket);
                break;
            case FIN:
            case RST:
                processClosed(natMessagePacket);
                break;
            case DATA:
                processData(natMessagePacket);
                break;
            case WINDOW_UPDATE:
                processWindowUpdate(natMessagePacket);
                break;
            case KEEPALIVE:
                // KEEPALIVE 是 NatCommonHandler 在 writer-idle 时主动发送的保活帧，静默接受即可。
                // 此前缺失该分支会导致入站 KEEPALIVE 落入 default 断开连接（自相矛盾）。
                break;
            default:
                log.warn("Unexpected NAT stream type: {}", natMessagePacket.getNatMessageType());
                ctx.close();
        }
    }

    private void processData(NatMessagePacket natMessagePacket) {
        byte[] data = natMessagePacket.getData();
        if (data == null) {
            log.warn("DATA frame with no payload from {}", clientName);
            return;
        }
        int streamId = natMessagePacket.getStreamId();
        HttpStreamForwarder http = httpStreams.get(streamId);
        if (http != null) {
            if (!http.onData(data)) {
                failHttpStream(streamId, "HTTP request queue or size limit exceeded");
            }
            return;
        }
        ChannelHandlerContext wsCtx = wsLocalChannels.get(streamId);
        if (wsCtx != null) {
            WsLocalTunnelHandler handler = wsCtx.pipeline().get(WsLocalTunnelHandler.class);
            if (handler == null) {
                return;
            }
            handler.writeFrame(wsCtx, data);
            sendWindowUpdate(streamId, data.length);
            if (!wsCtx.channel().isWritable()) {
                pauseControlReads();
            }
            return;
        }
        LocalTunnelHandler handler = channelHandlerMap.get(streamId);
        if (handler != null) {
            ChannelHandlerContext localCtx = handler.getCtx();
            if (localCtx == null) {
                return;
            }
            localCtx.writeAndFlush(data).addListener(future -> {
                if (!future.isSuccess()) {
                    localCtx.close();
                } else {
                    sendWindowUpdate(streamId, data.length);
                    if ((natMessagePacket.getFlags() & NatMessagePacket.FLAG_END_STREAM) != 0) {
                        shutdownOutput(localCtx.channel());
                    }
                }
            });
            if (!localCtx.channel().isWritable()) {
                pauseControlReads();
            }
        }
    }

    private void processClosed(NatMessagePacket natMessagePacket) {
        int streamId = natMessagePacket.getStreamId();
        HttpStreamForwarder http = httpStreams.get(streamId);
        if (http != null) {
            if (natMessagePacket.getNatMessageType() == NatMessageType.RST) {
                httpStreams.remove(streamId, http);
                http.cancel(asString(natMessagePacket.getMetaData(), "reason"));
                StreamFlowController.get(ctx.channel()).remove(streamId);
            } else {
                http.onRequestFin(natMessagePacket.getMetaData());
            }
            return;
        }
        ChannelHandlerContext wsCtx = wsLocalChannels.remove(streamId);
        if (wsCtx != null) {
            StreamFlowController.get(ctx.channel()).remove(streamId);
            wsCtx.close();
            return;
        }
        LocalTunnelHandler handler = channelHandlerMap.get(streamId);
        if (handler != null) {
            ChannelHandlerContext localCtx = handler.getCtx();
            if (localCtx != null) {
                if (natMessagePacket.getNatMessageType() == NatMessageType.RST) {
                    StreamFlowController.get(ctx.channel()).remove(streamId);
                    localCtx.close();
                } else {
                    shutdownOutput(localCtx.channel());
                }
            }
        }
    }

    private void processOpen(NatMessagePacket natMessagePacket) throws Exception {
        String source = asString(natMessagePacket.getMetaData(), "source");
        if ("http".equals(source)) {
            processHttpOpen(natMessagePacket);
        } else if ("ws".equals(source)) {
            processWsConnected(natMessagePacket);
        } else {
            processTcpConnected(natMessagePacket);
        }
    }

    private void processTcpConnected(NatMessagePacket natMessagePacket) throws Exception {
        try {
            NatClientHandler thisHandler = this;
            Integer port = asInt(natMessagePacket.getMetaData(), "port");
            if (port == null) {
                log.warn("CONNECTED frame missing port from {}", clientName);
                return;
            }
            String channelId = asString(natMessagePacket.getMetaData(), "channelId");
            if (channelId == null) {
                log.warn("CONNECTED frame missing channelId from {}", clientName);
                return;
            }
            TunnelConfig tunnelConfig = tunnelConfigMap.get(port);
            if (tunnelConfig == null) {
                log.warn("CONNECTED for unknown port {} from {}", port, clientName);
                return;
            }
            localConnection.connect(tunnelConfig.getTunnelAddress(), tunnelConfig.getTunnelPort(), new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel channel) throws Exception {
                    int streamId = natMessagePacket.getStreamId();
                    LocalTunnelHandler localTunnelHandler = new LocalTunnelHandler(thisHandler, streamId);
                    channel.pipeline().addLast(new ByteArrayDecoder(), new ByteArrayEncoder(), localTunnelHandler);
                    channelHandlerMap.put(streamId, localTunnelHandler);
                    channelGroup.add(channel);
                    syncLocalReadWithControl(channel);
                    channel.closeFuture().addListener(future -> {
                        removeLocalHandler(streamId, localTunnelHandler);
                    });
                }
            });
        } catch (Exception e) {
            sendReset(natMessagePacket.getStreamId(), 1, "local connect failed");
            channelHandlerMap.remove(natMessagePacket.getStreamId());
            throw e;
        }
    }

    /**
     * 服务端发来 source="ws" 的 CONNECTED：按 metaData 里的 route 查本地 {@code ws://} 目标，
     * 用 Netty WebSocket 客户端发起握手，握手成功后把本地 Channel 注册进 {@link #wsLocalChannels}。
     */
    private void processWsConnected(NatMessagePacket natMessagePacket) {
        NatClientHandler thisHandler = this;
        int streamId = natMessagePacket.getStreamId();
        String channelId = asString(natMessagePacket.getMetaData(), "channelId");
        String route = asString(natMessagePacket.getMetaData(), "route");
        if (channelId == null || route == null) {
            log.warn("[ws-tunnel][client] CONNECTED missing channelId/route from {}", clientName);
            sendReset(streamId, 2, "invalid websocket open");
            return;
        }
        Map<String, String> routes = httpRoutes;
        String targetBaseUrl = routes.get(route);
        if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
            log.warn("[ws-tunnel][client] CONNECTED for unknown route {} from {}", route, clientName);
            sendReset(streamId, 3, "unknown websocket route");
            return;
        }
        String relativePath = asString(natMessagePacket.getMetaData(), "relativePath");
        String rawQuery = asString(natMessagePacket.getMetaData(), "rawQuery");
        URI target;
        try {
            target = buildWsTarget(targetBaseUrl, relativePath, rawQuery);
        } catch (Exception e) {
            log.warn("[ws-tunnel][client] CONNECTED route={} build-target-failed error={}", route, e.getMessage());
            sendReset(streamId, 4, "invalid websocket target");
            return;
        }
        log.info("[ws-tunnel][client] CONNECTED channelId={} route={} target={}", channelId, route, withoutQuery(target));

        EventLoopGroup group = ensureWsWorkerGroup();
        Bootstrap b = new Bootstrap();
        b.group(group)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(32 * 1024, 64 * 1024))
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) throws Exception {
                        WebSocketClientHandshaker handshaker = WebSocketClientHandshakerFactory.newHandshaker(
                                target, WebSocketVersion.V13, null, true,
                                buildWsHandshakeHeaders(natMessagePacket), 65536);
                        ch.pipeline().addLast(new HttpClientCodec());
                        ch.pipeline().addLast(new HttpObjectAggregator(65536));
                        ch.pipeline().addLast(new WebSocketClientProtocolHandler(handshaker));
                        ch.pipeline().addLast(new WsLocalTunnelHandler(thisHandler, streamId, channelId));
                    }
                });
        b.connect(target.getHost(), target.getPort() == -1 ? defaultPort(target.getScheme()) : target.getPort())
                .addListener((ChannelFuture connectFuture) -> {
                    if (!connectFuture.isSuccess()) {
                        log.warn("[ws-tunnel][client] connect local ws failed channelId={} route={} error={}",
                                channelId, route, connectFuture.cause() == null ? "unknown" : connectFuture.cause().toString());
                        sendReset(streamId, 5, "websocket connect failed");
                        return;
                    }
                    Channel channel = connectFuture.channel();
                    // 握手完成由 WsLocalTunnelHandler.userEventTriggered(HANDSHAKE_COMPLETE) 感知，
                    // 成功后自动注册进 wsLocalChannels；失败则由握手超时/异常关闭触发 channelInactive，
                    // 此时 registered=false，不会重复发 DISCONNECTED。
                    channel.closeFuture().addListener(closeFuture -> {
                        ChannelHandlerContext removed = wsLocalChannels.remove(streamId);
                        if (removed != null) {
                            updateControlAutoReadForLocalWritability();
                        }
                    });
                });
    }

    /**
     * 由 {@link WsLocalTunnelHandler#userEventTriggered} 在握手成功时调用，把本地 Channel 注册进
     * wsLocalChannels。返回 false 表示控制连接已断开，调用方应关闭本地 Channel。
     */
    boolean registerWsLocalChannel(int streamId, ChannelHandlerContext localCtx) {
        if (ctx == null || !ctx.channel().isActive()) {
            return false;
        }
        wsLocalChannels.put(streamId, localCtx);
        log.info("[ws-tunnel][client] ws handshake ok streamId={} registered", Integer.toUnsignedString(streamId));
        return true;
    }

    void removeWsLocalHandler(int streamId, WsLocalTunnelHandler handler) {
        ChannelHandlerContext ctx = wsLocalChannels.get(streamId);
        if (ctx != null && ctx.pipeline().get(WsLocalTunnelHandler.class) == handler) {
            wsLocalChannels.remove(streamId);
            updateControlAutoReadForLocalWritability();
        }
    }

    private EventLoopGroup ensureWsWorkerGroup() {
        if (wsWorkerGroup != null && !wsWorkerGroup.isShuttingDown()) {
            return wsWorkerGroup;
        }
        synchronized (this) {
            if (wsWorkerGroup == null || wsWorkerGroup.isShuttingDown()) {
                wsWorkerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
            }
            return wsWorkerGroup;
        }
    }

    private static int defaultPort(String scheme) {
        return "wss".equalsIgnoreCase(scheme) ? 443 : 80;
    }

    private static String withoutQuery(URI uri) {
        return uri.getScheme() + "://" + uri.getHost() + ":" + (uri.getPort() == -1 ? defaultPort(uri.getScheme()) : uri.getPort()) + uri.getPath();
    }

    @SuppressWarnings("unchecked")
    private static io.netty.handler.codec.http.HttpHeaders buildWsHandshakeHeaders(NatMessagePacket natMessagePacket) {
        io.netty.handler.codec.http.HttpHeaders headers = new io.netty.handler.codec.http.DefaultHttpHeaders();
        Object headersObj = natMessagePacket.getMetaData() == null ? null : natMessagePacket.getMetaData().get("headers");
        if (headersObj instanceof List<?> list) {
            Set<String> skipped = Set.of("connection", "content-length", "host", "keep-alive",
                    "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding",
                    "upgrade", "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions",
                    "sec-websocket-protocol", "sec-websocket-accept");
            for (Object item : list) {
                if (!(item instanceof String line)) {
                    continue;
                }
                int sep = line.indexOf(':');
                if (sep <= 0) {
                    continue;
                }
                String name = line.substring(0, sep);
                if (skipped.contains(name.toLowerCase(Locale.ROOT))) {
                    continue;
                }
                headers.add(name, line.substring(sep + 1));
            }
        }
        return headers;
    }

    static URI buildWsTarget(String targetBaseUrl, String relativePath, String rawQuery) {
        if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
            throw new IllegalArgumentException("未配置 HTTP route");
        }
        String wsUrl = targetBaseUrl;
        // http:// -> ws://，https:// -> wss://。本轮仅支持 ws://（明文）；遇 https 转 wss 但本
        // 地 WS 客户端未配 TLS 上下文，握手会失败——这里先转，让握手阶段给出明确错误。
        if (wsUrl.startsWith("http://")) {
            wsUrl = "ws://" + wsUrl.substring("http://".length());
        } else if (wsUrl.startsWith("https://")) {
            wsUrl = "wss://" + wsUrl.substring("https://".length());
        } else if (!wsUrl.startsWith("ws://") && !wsUrl.startsWith("wss://")) {
            throw new IllegalArgumentException("HTTP route 仅支持 http/https/ws/wss");
        }
        URI base = URI.create(wsUrl);
        if (base.getHost() == null) {
            throw new IllegalArgumentException("HTTP route 地址无效");
        }
        if (base.getRawQuery() != null || base.getRawFragment() != null) {
            throw new IllegalArgumentException("HTTP route 地址无效");
        }
        String basePath = base.getPath() == null || base.getPath().isEmpty() ? "" : base.getPath();
        String tail = relativePath == null || relativePath.isBlank() ? "/" : relativePath;
        String path;
        if (basePath.endsWith("/") && tail.startsWith("/")) {
            path = basePath + tail.substring(1);
        } else if (!basePath.isEmpty() && !basePath.endsWith("/") && !tail.startsWith("/")) {
            path = basePath + "/" + tail;
        } else {
            path = basePath + tail;
        }
        int authorityEnd = wsUrl.indexOf('/', wsUrl.indexOf("://") + 3);
        String authority = authorityEnd < 0 ? wsUrl : wsUrl.substring(0, authorityEnd);
        String full = authority + path
                + (rawQuery == null || rawQuery.isBlank() ? "" : "?" + rawQuery);
        return URI.create(full);
    }

    private void processHttpOpen(NatMessagePacket packet) {
        if (!"request".equals(asString(packet.getMetaData(), "phase"))) {
            sendReset(packet.getStreamId(), 7, "invalid HTTP OPEN phase");
            return;
        }
        int streamId = packet.getStreamId();
        HttpStreamForwarder forwarder = new HttpStreamForwarder(
                this, streamId, packet.getMetaData(), httpRoutes);
        if (httpStreams.putIfAbsent(streamId, forwarder) != null) {
            sendReset(streamId, 7, "duplicate HTTP stream");
            return;
        }
        StreamFlowController.get(ctx.channel()).open(streamId, null);
        forwarder.start();
    }

    CompletableFuture<Void> sendHttpResponseHead(int streamId, int statusCode, List<String> headers) {
        if (!httpStreams.containsKey(streamId) || ctx == null || !ctx.channel().isActive()) {
            return CompletableFuture.failedFuture(new IllegalStateException("HTTP stream is closed"));
        }
        NatMessagePacket open = new NatMessagePacket();
        open.setNatMessageType(NatMessageType.OPEN);
        open.setStreamId(streamId);
        open.setMetaData(Map.of(
                "source", "http",
                "phase", "response",
                "statusCode", statusCode,
                "headers", headers == null ? List.of() : List.copyOf(headers)));
        CompletableFuture<Void> completion = new CompletableFuture<>();
        ctx.writeAndFlush(open).addListener(result -> {
            if (result.isSuccess()) completion.complete(null);
            else completion.completeExceptionally(result.cause());
        });
        return completion;
    }

    CompletableFuture<Void> sendHttpResponseData(int streamId, byte[] data) {
        if (ctx == null || !httpStreams.containsKey(streamId)) {
            return CompletableFuture.failedFuture(new IllegalStateException("HTTP stream is closed"));
        }
        return StreamFlowController.get(ctx.channel()).sendAsync(streamId, data, null,
                () -> httpStreams.remove(streamId));
    }

    CompletableFuture<Void> finishHttpResponse(int streamId, List<String> trailers) {
        if (ctx == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("control channel is closed"));
        }
        Map<String, Object> metadata = trailers == null || trailers.isEmpty()
                ? null : Map.of("trailers", List.copyOf(trailers));
        return StreamFlowController.get(ctx.channel()).finishAsync(streamId, metadata);
    }

    void sendHttpWindowUpdate(int streamId, int bytes) {
        sendWindowUpdate(streamId, bytes);
    }

    void failHttpStream(int streamId, String reason) {
        HttpStreamForwarder stream = httpStreams.remove(streamId);
        if (stream != null) {
            stream.cancel(reason);
        }
        sendReset(streamId, 8, reason);
    }

    void httpForwarderDone(int streamId, HttpStreamForwarder forwarder) {
        httpStreams.remove(streamId, forwarder);
    }

    private void sendReset(int streamId, long errorCode, String reason) {
        StreamFlowController.get(ctx.channel()).reset(streamId, errorCode, reason);
    }

    private void sendWindowUpdate(int streamId, int credit) {
        if (ctx == null || credit <= 0) {
            return;
        }
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.WINDOW_UPDATE);
        message.setStreamId(streamId);
        message.setValue(Integer.toUnsignedLong(credit));
        ctx.writeAndFlush(message);
    }

    private void processWindowUpdate(NatMessagePacket packet) {
        StreamFlowController.get(ctx.channel()).onWindowUpdate(packet.getStreamId(), packet.getValue());
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        StreamFlowController.get(ctx.channel()).onControlWritabilityChanged();
        updateLocalAutoReadForControlWritability();
        updateControlAutoReadForLocalWritability();
        super.channelWritabilityChanged(ctx);
    }

    void updateControlAutoReadForLocalWritability() {
        if (ctx != null) {
            ChannelBackpressure.setAutoRead(ctx.channel(), ctx.channel().isWritable() && localChannelsWritable());
        }
    }

    void removeLocalHandler(int streamId, LocalTunnelHandler handler) {
        if (channelHandlerMap.remove(streamId, handler)) {
            updateControlAutoReadForLocalWritability();
        }
    }

    private void pauseControlReads() {
        if (ctx != null) {
            ChannelBackpressure.setAutoRead(ctx.channel(), false);
        }
    }

    private void updateLocalAutoReadForControlWritability() {
        if (ctx == null) {
            return;
        }
        boolean controlWritable = ctx.channel().isWritable();
        channelGroup.forEach(channel -> ChannelBackpressure.setAutoRead(channel, controlWritable));
        // WS 本地 Channel 不在 channelGroup 里（握手前还不算"已建立"），单独处理
        wsLocalChannels.values().forEach(localCtx -> ChannelBackpressure.setAutoRead(localCtx.channel(), controlWritable));
    }

    void syncLocalReadWithControl(Channel channel) {
        if (ctx != null) {
            ChannelBackpressure.setAutoRead(channel, ctx.channel().isWritable());
        }
    }

    private static void shutdownOutput(Channel channel) {
        if (channel instanceof DuplexChannel duplexChannel) {
            duplexChannel.shutdownOutput();
        } else {
            channel.close();
        }
    }

    private boolean localChannelsWritable() {
        if (!ChannelBackpressure.allWritable(channelGroup)) {
            return false;
        }
        for (ChannelHandlerContext wsCtx : wsLocalChannels.values()) {
            if (!wsCtx.channel().isWritable()) {
                return false;
            }
        }
        return true;
    }

    private synchronized void processRegisterResult(NatMessagePacket natMessagePacket) {
        Map<String, Object> meta = natMessagePacket.getMetaData();
        Object successObj = meta == null ? null : meta.get("success");
        boolean success = successObj instanceof Boolean b && b;
        Integer port = asInt(meta, "port");
        if (success) {
            if (port == null) {
                log.info("Register result missing port [{}]", clientName);
                return;
            }
            TunnelConfig tunnelConfig = tunnelConfigMap.get(port);
            if (tunnelConfig == null) {
                log.info("Register result arrived after NAT port {} was removed", port);
            } else {
                log.info("Register to Nat server, {}:{}-->{}:{}", remoteHost, port, tunnelConfig.getTunnelAddress(), tunnelConfig.getTunnelPort());
            }
        } else {
            if (port != null) {
                registeredPorts.remove(port);
            }
            log.info("Register fail: {}", meta == null ? "(no metadata)" : meta.get("reason"));
        }
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
}
