package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.bean.TunnelConfig;
import com.theshuai.tunnelclient.client.TcpConnection;
import io.netty.channel.ChannelHandler;
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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@ChannelHandler.Sharable
public class NatClientHandler extends NatCommonHandler {

    private String remoteHost;

    private Map<Integer, TunnelConfig> tunnelConfigMap = new HashMap<>();

    private ConcurrentHashMap<String, NatCommonHandler> channelHandlerMap = new ConcurrentHashMap<>();
    private ChannelGroup channelGroup = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    private final Set<Integer> registeredPorts = new HashSet<>();
    private final String clientName;

    public NatClientHandler(TunnelBean tunnelBean) {
        this.remoteHost = tunnelBean.getRemoteAddress();
        this.clientName = tunnelBean.getClientName();
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
        channelGroup.close();
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
        String channelId = asString(natMessagePacket.getMetaData(), "channelId");
        if (channelId == null) {
            log.warn("DATA frame missing channelId from {}", clientName);
            return;
        }
        NatCommonHandler handler = channelHandlerMap.get(channelId);
        if (handler != null) {
            ChannelHandlerContext ctx = handler.getCtx();
            ctx.writeAndFlush(natMessagePacket.getData());
        }
    }

    private void processDisconnected(NatMessagePacket natMessagePacket) {
        String channelId = asString(natMessagePacket.getMetaData(), "channelId");
        if (channelId == null) {
            return;
        }
        NatCommonHandler handler = channelHandlerMap.get(channelId);
        if (handler != null) {
            handler.getCtx().close();
            channelHandlerMap.remove(channelId);
        }
    }

    private void processConnected(NatMessagePacket natMessagePacket) throws Exception {
        try {
            NatClientHandler thisHandler = this;
            TcpConnection localConnection = new TcpConnection();
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
