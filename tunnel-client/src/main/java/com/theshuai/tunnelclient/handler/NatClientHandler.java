package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.bean.TunnelConfig;
import com.theshuai.tunnelclient.client.NettyClient;
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

    public NatClientHandler(TunnelBean tunnelBean) {
        this.remoteHost = tunnelBean.getRemoteAddress();
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
            metaData.put("clientName", NettyClient.CLIENT_NAME);
            message.setMetaData(metaData);
            ctx.writeAndFlush(message);
        }
    }

    public synchronized void applyConfig(TunnelBean tunnelBean) {
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
        String channelId = natMessagePacket.getMetaData().get("channelId").toString();
        NatCommonHandler handler = channelHandlerMap.get(channelId);
        if (handler != null) {
            ChannelHandlerContext ctx = handler.getCtx();
            ctx.writeAndFlush(natMessagePacket.getData());
        }
    }

    private void processDisconnected(NatMessagePacket natMessagePacket) {
        String channelId = natMessagePacket.getMetaData().get("channelId").toString();
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
            Integer port = (Integer) natMessagePacket.getMetaData().get("port");
            TunnelConfig tunnelConfig = tunnelConfigMap.get(port);
            localConnection.connect(tunnelConfig.getTunnelAddress(), tunnelConfig.getTunnelPort(), new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel channel) throws Exception {
                    LocalTunnelHandler localTunnelHandler = new LocalTunnelHandler(thisHandler, natMessagePacket.getMetaData().get("channelId").toString());
                    channel.pipeline().addLast(new ByteArrayDecoder(), new ByteArrayEncoder(), localTunnelHandler);
                    channelHandlerMap.put(natMessagePacket.getMetaData().get("channelId").toString(), localTunnelHandler);
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
            channelHandlerMap.remove(natMessagePacket.getMetaData().get("channelId").toString());
            throw e;
        }
    }

    private void processRegisterResult(NatMessagePacket natMessagePacket) {
        if (((Boolean) natMessagePacket.getMetaData().get("success"))) {
            int port = (int) natMessagePacket.getMetaData().get("port");
            TunnelConfig tunnelConfig = tunnelConfigMap.get(port);
            if (tunnelConfig == null) {
                log.info("Register result arrived after NAT port {} was removed", port);
            } else {
                log.info("Register to Nat server, {}:{}-->{}:{}", remoteHost, port, tunnelConfig.getTunnelAddress(), tunnelConfig.getTunnelPort());
            }
        } else {
            log.info("Register fail: " + natMessagePacket.getMetaData().get("reason"));
            ctx.close();
        }
    }
}
