package com.theshuai.tunnelserver.handler;

import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.tunnelserver.server.TcpServer;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.SessionUtil;
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
import java.util.Map;

@Slf4j
@ChannelHandler.Sharable
public class NatServerHandler extends NatCommonHandler {
    private Map<Integer, TcpServer> remoteConnectionServerMap = new HashMap<>();

    private static final ChannelGroup channelGroup = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    private boolean register = false;
    private final TrafficUsageService trafficUsageService;
    private String clientName;

    public NatServerHandler(TrafficUsageService trafficUsageService) {
        this.trafficUsageService = trafficUsageService;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof NatMessagePacket) {
            NatMessagePacket natMessagePacket = (NatMessagePacket) msg;
            if (natMessagePacket.getNatMessageType() == NatMessageType.REGISTER) {
                processRegister(natMessagePacket);
            } else if (natMessagePacket.getNatMessageType() == NatMessageType.UNREGISTER) {
                processUnregister(natMessagePacket);
            } else if (register) {
                switch (natMessagePacket.getNatMessageType()) {
                    case DISCONNECTED:
                        processDisconnected(natMessagePacket);
                        break;
                    case DATA:
                        processData(natMessagePacket);
                        break;
                    default:
                        log.info("unknown type : {}", natMessagePacket.getNatMessageType());
                }
            } else {
                ctx.close();
            }
        } else {
            super.channelRead(ctx, msg);
        }
    }

    private void processData(NatMessagePacket natMessagePacket) {
        trafficUsageService.recordUpload(clientName, natMessagePacket.getData().length);
        channelGroup.writeAndFlush(natMessagePacket.getData(), channel -> channel.id().asLongText().equals(natMessagePacket.getMetaData().get("channelId")));
    }

    private void processDisconnected(NatMessagePacket natMessagePacket) {
        channelGroup.close(channel -> channel.id().asLongText().equals(natMessagePacket.getMetaData().get("channelId")));
    }

    private void processUnregister(NatMessagePacket natMessagePacket) {
        int port = (int) natMessagePacket.getMetaData().get("port");
        TcpServer server = remoteConnectionServerMap.remove(port);
        if (server != null) {
            server.close();
            log.info("Stop server on port: {} [{}]", port, clientName);
        }
    }

    private void processRegister(NatMessagePacket natMessagePacket) {
        Map<String, Object> metaData = new HashMap<>();
        int port = (int) natMessagePacket.getMetaData().get("port");
        String tunnelAddress = natMessagePacket.getMetaData().get("tunnelAddress").toString();
        int tunnelPort = (int) natMessagePacket.getMetaData().get("tunnelPort");
        Session session = SessionUtil.getSession(ctx.channel());
        String requestedClientName = natMessagePacket.getMetaData().get("clientName").toString();
        if (session == null || !session.getClientName().equals(requestedClientName)) {
            ctx.close();
            return;
        }
        clientName = session.getClientName();
        metaData.put("port", port);
        if (remoteConnectionServerMap.containsKey(port)) {
            metaData.put("success", true);
            writeRegisterResult(metaData);
            return;
        }
        try {
            NatServerHandler thisHandler = this;
            final TcpServer remoteConnectionServer = new TcpServer();
            remoteConnectionServer.bind(port, new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel channel) throws Exception {
                    channel.pipeline().addLast(new ByteArrayDecoder(), new ByteArrayEncoder(), new RemoteTunnelHandler(thisHandler, port, clientName, trafficUsageService));
                    channelGroup.add(channel);
                }
            });

            metaData.put("success", true);
            remoteConnectionServerMap.put(port, remoteConnectionServer);
            register = true;
            log.info("register success, start server on port {} --> {}:{} [{}] ", port, tunnelAddress, tunnelPort, clientName);
        } catch (Exception e) {
            metaData.put("success", false);
            metaData.put("reason", e.getMessage());
            e.printStackTrace();
        }

        writeRegisterResult(metaData);

        if (!register) {
            log.info("Client register error: " + metaData.get("reason"));
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
        log.info(ctx.channel().id().asLongText() + " inactive close");
        for (Map.Entry<Integer, TcpServer> serverEntry : remoteConnectionServerMap.entrySet()) {
            serverEntry.getValue().close();
            if (register) {
                log.info("Stop server on port: {}", serverEntry.getKey());
            }
        }
        remoteConnectionServerMap = new HashMap<>();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        log.info(ctx.channel().id().asLongText() + " exception happen");
        super.exceptionCaught(ctx, cause);
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        remoteConnectionServerMap.values().forEach(TcpServer::close);
        super.channelUnregistered(ctx);
    }
}
