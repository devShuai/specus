package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.bean.TunnelConfig;
import com.theshuai.tunnelclient.client.TcpConnection;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.bytes.ByteArrayDecoder;
import io.netty.handler.codec.bytes.ByteArrayEncoder;
import io.netty.util.concurrent.GlobalEventExecutor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class NatClientHandler extends NatCommonHandler {

    private String remoteHost;

    private Map<Integer, TunnelConfig> tunnelConfigMap = new HashMap<>();

    private ConcurrentHashMap<String, LocalTunnelHandler> channelHandlerMap = new ConcurrentHashMap<>();
    private ChannelGroup channelGroup = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    private final Set<Integer> registeredPorts = new HashSet<>();
    private final String clientName;
    private final TcpConnection localConnection;
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
     * 与"老客户端未上报"。
     *
     * <p>历史背景：早期版本服务端会读这条上报来填面板（{@code HttpRouteRegistry}）。改为
     * 服务端持久化模型后，这条消息变成纯诊断（服务端目前 log 即丢），保留是为了让旧版
     * 服务端仍能正常显示客户端连进来的路由信息。
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
        localConnection.close();
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
        LocalTunnelHandler handler = channelHandlerMap.remove(channelId);
        if (handler != null) {
            ChannelHandlerContext localCtx = handler.getCtx();
            if (localCtx != null) {
                localCtx.close();
            }
        }
    }

    private void processConnected(NatMessagePacket natMessagePacket) throws Exception {
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
            NatMessagePacket message = new NatMessagePacket();
            message.setNatMessageType(NatMessageType.DISCONNECTED);
            Map<String, Object> metaData = new HashMap<>();
            metaData.put("channelId", natMessagePacket.getMetaData().get("channelId"));
            message.setMetaData(metaData);
            ctx.writeAndFlush(message);
            String channelId = asString(natMessagePacket.getMetaData(), "channelId");
            if (channelId != null) {
                channelHandlerMap.remove(channelId);
            }
            throw e;
        }
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
    }

    private void syncLocalReadWithControl(Channel channel) {
        if (ctx != null) {
            ChannelBackpressure.setAutoRead(channel, ctx.channel().isWritable());
        }
    }

    private boolean localChannelsWritable() {
        return ChannelBackpressure.allWritable(channelGroup);
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
