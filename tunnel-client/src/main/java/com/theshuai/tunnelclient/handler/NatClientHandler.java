package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.ChannelBackpressure;
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

@Slf4j
public class NatClientHandler extends NatCommonHandler {

    private String remoteHost;

    private Map<Integer, TunnelConfig> tunnelConfigMap = new HashMap<>();

    /**
     * HTTP 路由快照（route → targetBaseUrl）。WS 隧道 CONNECTED 帧到达时按 route 查本地
     * {@code ws://} 目标。volatile 整体替换，与 {@link DirectHttpRequestHandler#routes} 同步更新。
     */
    private volatile Map<String, String> httpRoutes = Map.of();

    private ConcurrentHashMap<String, LocalTunnelHandler> channelHandlerMap = new ConcurrentHashMap<>();
    /** WS 隧道流的本地 Channel，key = 服务端分配的 channelId。与 {@link #channelHandlerMap} 平行。 */
    private final ConcurrentHashMap<String, ChannelHandlerContext> wsLocalChannels = new ConcurrentHashMap<>();
    private ChannelGroup channelGroup = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    private final Set<Integer> registeredPorts = new HashSet<>();
    private final String clientName;
    private final TcpConnection localConnection;
    /** 本地 WS 连接用的独立 EventLoopGroup（复用 {@link TcpConnection} 的 group 也可，这里独立以便清晰）。 */
    private EventLoopGroup wsWorkerGroup;
    /**
     * 仅用于上报给服务端做诊断（"客户端实际生效的 HTTP 路由"）。每个新建 channel 由
     * {@link #handlerAdded} / {@link #channelActive} 触发一次上报，{@code channelInactive}
     * 重置以便重连后再发。**路由数据本身**不持有在这里——上报时去 pipeline 中的
     * {@code DirectHttpRequestHandler.getCurrentRoutes()} 取，保证服务端 push 热更新后
     * 的最新值能反映在下次上报里。
     */
    private boolean httpRoutesReported;

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
     * 与 {@link DirectHttpRequestHandler#applyRoutes} 同步替换。
     */
    public void applyHttpRoutes(List<HttpTunnelConfig> next) {
        this.httpRoutes = toHttpRouteMap(next);
        log.info("[ws-tunnel][client] httpRoutes updated: {} entries", httpRoutes.size());
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
            reportHttpRoutes(ctx);
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        registerTunnels(ctx);
        reportHttpRoutes(ctx);
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

    /**
     * 把"客户端当前实际生效"的 HTTP 路由列表上报给服务端做诊断。每次新 channel 只发一次；
     * channelInactive 时复位标志位，重连后会再次上报。空列表也发，让服务端能区分"未配置"
     * 与"本次还未上报"。
     */
    private synchronized void reportHttpRoutes(ChannelHandlerContext ctx) {
        if (httpRoutesReported) {
            return;
        }
        httpRoutesReported = true;
        // 从 pipeline 中拿"当前生效"的 routes，而不是构造期那份——保证服务端 push 热更新后
        // 下次上报反映的是最新值。pipeline 顺序保证 DirectHttpRequestHandler 先于 NatClientHandler
        // 加入（NettyClient.start 的 initChannel）。
        DirectHttpRequestHandler directHttp = ctx.pipeline().get(DirectHttpRequestHandler.class);
        Map<String, String> liveRoutes = directHttp == null ? Map.of() : directHttp.getCurrentRoutes();
        List<Map<String, String>> routes = new ArrayList<>(liveRoutes.size());
        for (Map.Entry<String, String> entry : liveRoutes.entrySet()) {
            String route = entry.getKey();
            if (!StringUtils.hasText(route)) {
                continue;
            }
            Map<String, String> item = new HashMap<>(2);
            item.put("route", route);
            item.put("targetBaseUrl", entry.getValue() == null ? "" : entry.getValue());
            routes.add(item);
        }
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.HTTP_ROUTES_REPORT);
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("clientName", clientName);
        metaData.put("routes", routes);
        message.setMetaData(metaData);
        ctx.writeAndFlush(message);
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
        channelGroup.close();
        channelHandlerMap.clear();
        wsLocalChannels.values().forEach(ch -> ch.close());
        wsLocalChannels.clear();
        localConnection.close();
        if (wsWorkerGroup != null) {
            EventLoopGroup toShutdown = wsWorkerGroup;
            wsWorkerGroup = null;
            toShutdown.shutdownGracefully();
        }
        // 重连时新 handler 实例会重置；同一实例（NAT_CONTROL 复用）也允许再次上报
        httpRoutesReported = false;
        log.info("Loss connection to Nat server... Please restart!");
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof NatMessagePacket) {
            NatMessagePacket natMessagePacket = (NatMessagePacket) msg;
            switch (natMessagePacket.getNatMessageType()) {
                case REGISTER_RESULT:
                    processRegisterResult(natMessagePacket);
                    break;
                case CONNECTED:
                    processConnected(natMessagePacket);
                    break;
                case DISCONNECTED:
                    processDisconnected(natMessagePacket);
                    break;
                case DATA:
                    processData(natMessagePacket);
                    break;
                default:
                    log.info("Unknown type");
            }
        }
    }

    private void processData(NatMessagePacket natMessagePacket) {
        byte[] data = natMessagePacket.getData();
        if (data == null) {
            log.warn("DATA frame with no payload from {}", clientName);
            return;
        }
        String channelId = asString(natMessagePacket.getMetaData(), "channelId");
        if (channelId == null) {
            log.warn("DATA frame missing channelId from {}", clientName);
            return;
        }
        // WS 流优先（source="ws" 或 channelId 命中 wsLocalChannels）
        ChannelHandlerContext wsCtx = wsLocalChannels.get(channelId);
        if (wsCtx != null) {
            WsLocalTunnelHandler handler = wsCtx.pipeline().get(WsLocalTunnelHandler.class);
            if (handler == null) {
                return;
            }
            handler.writeFrame(wsCtx, data);
            if (!wsCtx.channel().isWritable()) {
                pauseControlReads();
            }
            return;
        }
        LocalTunnelHandler handler = channelHandlerMap.get(channelId);
        if (handler != null) {
            ChannelHandlerContext localCtx = handler.getCtx();
            if (localCtx == null) {
                return;
            }
            localCtx.writeAndFlush(data).addListener(future -> {
                if (!future.isSuccess()) {
                    localCtx.close();
                }
            });
            if (!localCtx.channel().isWritable()) {
                pauseControlReads();
            }
        }
    }

    private void processDisconnected(NatMessagePacket natMessagePacket) {
        String channelId = asString(natMessagePacket.getMetaData(), "channelId");
        if (channelId == null) {
            return;
        }
        ChannelHandlerContext wsCtx = wsLocalChannels.remove(channelId);
        if (wsCtx != null) {
            wsCtx.close();
            return;
        }
        LocalTunnelHandler handler = channelHandlerMap.remove(channelId);
        if (handler != null) {
            ChannelHandlerContext localCtx = handler.getCtx();
            if (localCtx != null) {
                localCtx.close();
            }
        }
    }

    private void processConnected(NatMessagePacket natMessagePacket) throws Exception {
        String source = asString(natMessagePacket.getMetaData(), "source");
        if ("ws".equals(source)) {
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
                    LocalTunnelHandler localTunnelHandler = new LocalTunnelHandler(thisHandler, channelId);
                    channel.pipeline().addLast(new ByteArrayDecoder(), new ByteArrayEncoder(), localTunnelHandler);
                    channelHandlerMap.put(channelId, localTunnelHandler);
                    channelGroup.add(channel);
                    syncLocalReadWithControl(channel);
                    channel.closeFuture().addListener(future -> {
                        removeLocalHandler(channelId, localTunnelHandler);
                    });
                }
            });
        } catch (Exception e) {
            sendDisconnected(natMessagePacket.getMetaData());
            String channelId = asString(natMessagePacket.getMetaData(), "channelId");
            if (channelId != null) {
                channelHandlerMap.remove(channelId);
            }
            throw e;
        }
    }

    /**
     * 服务端发来 source="ws" 的 CONNECTED：按 metaData 里的 route 查本地 {@code ws://} 目标，
     * 用 Netty WebSocket 客户端发起握手，握手成功后把本地 Channel 注册进 {@link #wsLocalChannels}。
     */
    private void processWsConnected(NatMessagePacket natMessagePacket) {
        NatClientHandler thisHandler = this;
        String channelId = asString(natMessagePacket.getMetaData(), "channelId");
        String route = asString(natMessagePacket.getMetaData(), "route");
        if (channelId == null || route == null) {
            log.warn("[ws-tunnel][client] CONNECTED missing channelId/route from {}", clientName);
            sendDisconnected(natMessagePacket.getMetaData());
            return;
        }
        Map<String, String> routes = httpRoutes;
        String targetBaseUrl = routes.get(route);
        if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
            log.warn("[ws-tunnel][client] CONNECTED for unknown route {} from {}", route, clientName);
            sendDisconnected(natMessagePacket.getMetaData());
            return;
        }
        String relativePath = asString(natMessagePacket.getMetaData(), "relativePath");
        String rawQuery = asString(natMessagePacket.getMetaData(), "rawQuery");
        URI target;
        try {
            target = buildWsTarget(targetBaseUrl, relativePath, rawQuery);
        } catch (Exception e) {
            log.warn("[ws-tunnel][client] CONNECTED route={} build-target-failed error={}", route, e.getMessage());
            sendDisconnected(natMessagePacket.getMetaData());
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
                        ch.pipeline().addLast(new WsLocalTunnelHandler(thisHandler, channelId));
                    }
                });
        b.connect(target.getHost(), target.getPort() == -1 ? defaultPort(target.getScheme()) : target.getPort())
                .addListener((ChannelFuture connectFuture) -> {
                    if (!connectFuture.isSuccess()) {
                        log.warn("[ws-tunnel][client] connect local ws failed channelId={} route={} error={}",
                                channelId, route, connectFuture.cause() == null ? "unknown" : connectFuture.cause().toString());
                        sendDisconnected(natMessagePacket.getMetaData());
                        return;
                    }
                    Channel channel = connectFuture.channel();
                    // 握手完成由 WsLocalTunnelHandler.userEventTriggered(HANDSHAKE_COMPLETE) 感知，
                    // 成功后自动注册进 wsLocalChannels；失败则由握手超时/异常关闭触发 channelInactive，
                    // 此时 registered=false，不会重复发 DISCONNECTED。
                    channel.closeFuture().addListener(closeFuture -> {
                        ChannelHandlerContext removed = wsLocalChannels.remove(channelId);
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
    boolean registerWsLocalChannel(String channelId, ChannelHandlerContext localCtx) {
        if (ctx == null || !ctx.channel().isActive()) {
            return false;
        }
        wsLocalChannels.put(channelId, localCtx);
        log.info("[ws-tunnel][client] ws handshake ok channelId={} registered", channelId);
        return true;
    }

    void removeWsLocalHandler(String channelId, WsLocalTunnelHandler handler) {
        ChannelHandlerContext ctx = wsLocalChannels.get(channelId);
        if (ctx != null && ctx.pipeline().get(WsLocalTunnelHandler.class) == handler) {
            wsLocalChannels.remove(channelId);
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

    private void sendDisconnected(Map<String, Object> metaData) {
        String channelId = asString(metaData, "channelId");
        if (channelId == null) {
            return;
        }
        NatMessagePacket message = new NatMessagePacket();
        message.setNatMessageType(NatMessageType.DISCONNECTED);
        Map<String, Object> meta = new HashMap<>();
        meta.put("channelId", channelId);
        meta.put("source", "ws");
        message.setMetaData(meta);
        ctx.writeAndFlush(message);
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        updateLocalAutoReadForControlWritability();
        updateControlAutoReadForLocalWritability();
        super.channelWritabilityChanged(ctx);
    }

    void updateControlAutoReadForLocalWritability() {
        if (ctx != null) {
            ChannelBackpressure.setAutoRead(ctx.channel(), ctx.channel().isWritable() && localChannelsWritable());
        }
    }

    void removeLocalHandler(String channelId, LocalTunnelHandler handler) {
        if (channelHandlerMap.remove(channelId, handler)) {
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

    private void processRegisterResult(NatMessagePacket natMessagePacket) {
        Map<String, Object> meta = natMessagePacket.getMetaData();
        Object successObj = meta == null ? null : meta.get("success");
        boolean success = successObj instanceof Boolean b && b;
        if (success) {
            Integer port = asInt(meta, "port");
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
            log.info("Register fail: {}", meta == null ? "(no metadata)" : meta.get("reason"));
            ctx.close();
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
