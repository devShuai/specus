package com.theshuai.tunnelserver.handler;

import com.theshuai.common.handler.ChannelBackpressure;
import com.theshuai.common.handler.NatCommonHandler;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.tunnelserver.session.SessionUtil;
import com.theshuai.tunnelserver.config.NettyServerProperties;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.tunnelserver.server.RemotePortServerManager;
import com.theshuai.tunnelserver.server.TcpServer;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.bytes.ByteArrayDecoder;
import io.netty.handler.codec.bytes.ByteArrayEncoder;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class NatServerHandler extends NatCommonHandler {
    // Pinned by client control connection: listenPort -> bound TcpServer.
    // Concurrent because the channel pipeline reads from arbitrary event loops.
    private final Map<Integer, TcpServer> remoteConnectionServerMap = new ConcurrentHashMap<>();

    // Public-internet channels for THIS client's tunnels, keyed by channelId.
    // Per-connection (not static) so DATA/DISCONNECTED routing is O(1) and a client can only
    // ever reach its own external channels. Concurrent because the accepted channels live on
    // their TcpServer's event loops while routing happens on the control connection's loop.
    private final Map<String, Channel> externalChannels = new ConcurrentHashMap<>();

    private final TrafficUsageService trafficUsageService;
    private final RemotePortServerManager remotePortServerManager;
    private final NettyServerProperties nettyProperties;
    private final AtomicInteger activeClientExternalChannels = new AtomicInteger();
    private final Map<Integer, AtomicInteger> portExternalChannelCounts = new ConcurrentHashMap<>();
    // Set during processRegister; null means the client has not registered any tunnel yet.
    private volatile String clientName;
    // Per-connection flag. Each control connection gets its own handler instance, but we still
    // gate DATA/DISCONNECTED on successful REGISTER to reject out-of-order messages.
    private volatile boolean register = false;

    public NatServerHandler(TrafficUsageService trafficUsageService,
                            RemotePortServerManager remotePortServerManager,
                            NettyServerProperties nettyProperties) {
        this.trafficUsageService = trafficUsageService;
        this.remotePortServerManager = remotePortServerManager;
        this.nettyProperties = nettyProperties;
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
        } else if (register) {
            switch (type) {
                case DISCONNECTED -> processDisconnected(natMessagePacket);
                case DATA -> processData(natMessagePacket);
                default -> log.info("unknown type : {}", type);
            }
        } else {
            // DATA / DISCONNECTED before any REGISTER — close to drop a misbehaving client.
            log.warn("Dropping {} before REGISTER on channel {}", type, ctx.channel().id().asLongText());
            ctx.close();
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
        Channel target = externalChannels.get(channelId);
        if (target == null) {
            return;
        }
        trafficUsageService.recordUpload(clientName, data.length);
        target.writeAndFlush(data).addListener(future -> {
            if (!future.isSuccess()) {
                log.warn("write DATA to external channel {} failed [{}]",
                        target.id().asLongText(), clientName, future.cause());
                target.close();
            }
        });
        if (!target.isWritable()) {
            pauseControlReads();
        }
    }

    private void processDisconnected(NatMessagePacket natMessagePacket) {
        String channelId = asString(natMessagePacket.getMetaData(), "channelId");
        if (channelId == null) {
            return;
        }
        Channel target = externalChannels.get(channelId);
        if (target != null) {
            target.close();
        }
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
            ctx.close();
            return;
        }

        Session session = SessionUtil.getSession(ctx.channel());
        if (session == null || !session.getClientName().equals(requestedClientName)) {
            // Claiming a different client name than the auth session — kick.
            log.warn("REGISTER clientName mismatch: session={}, claimed={}", session, requestedClientName);
            ctx.close();
            return;
        }
        clientName = session.getClientName();

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
                    try {
                        String channelId = channel.id().asLongText();
                        channel.pipeline().addLast(new ByteArrayDecoder(), new ByteArrayEncoder(),
                                new RemoteTunnelHandler(thisHandler, port, clientName, trafficUsageService));
                        externalChannels.put(channelId, channel);
                        syncExternalReadWithControl(channel);
                        channel.closeFuture().addListener(future -> {
                            if (externalChannels.remove(channelId) != null) {
                                releaseExternalChannel(port);
                                updateControlAutoReadForExternalWritability();
                            }
                        });
                    } catch (RuntimeException e) {
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
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        log.info("{} exception happen", ctx.channel().id().asLongText());
        super.exceptionCaught(ctx, cause);
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        remoteConnectionServerMap.values().forEach(TcpServer::close);
        super.channelUnregistered(ctx);
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
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
        if (!remotePortServerManager.tryAcquireExternalConnection()) {
            return false;
        }
        if (!tryIncrement(activeClientExternalChannels, nettyProperties.getMaxExternalConnectionsPerClient())) {
            remotePortServerManager.releaseExternalConnection();
            remotePortServerManager.recordRejectedExternalConnection();
            return false;
        }
        AtomicInteger portCounter = portExternalChannelCounts.computeIfAbsent(port, key -> new AtomicInteger());
        if (!tryIncrement(portCounter, nettyProperties.getMaxExternalConnectionsPerPort())) {
            decrement(activeClientExternalChannels);
            remotePortServerManager.releaseExternalConnection();
            remotePortServerManager.recordRejectedExternalConnection();
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
        remotePortServerManager.releaseExternalConnection();
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
}
