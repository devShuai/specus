package com.theshuai.specusserver.server;


import com.theshuai.common.codec.PacketCodecHandler;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.handler.HeartbeatRequestHandler;
import com.theshuai.common.handler.SocketIdleStateHandler;
import com.theshuai.specusserver.handler.AuthHandler;
import com.theshuai.specusserver.handler.ControlProtocolMetricsHandler;
import com.theshuai.specusserver.handler.ConnectionRoleHandler;
import com.theshuai.specusserver.handler.LogoutRequestHandler;
import com.theshuai.specusserver.handler.ServerMessageHandler;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.handler.ManagedLoginRequestHandler;
import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import com.theshuai.specusserver.security.TlsContextFactory;
import com.theshuai.specusserver.security.TlsProperties;
import com.theshuai.specusserver.http.WebSocketStreamRegistry;
import com.theshuai.specusserver.http.WebSocketSpecusHandler;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import jakarta.annotation.PreDestroy;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

@Component
@Slf4j
public class NettyServer implements ApplicationRunner {
    private final NettyServerProperties nettyProperties;
    private final ManagedLoginRequestHandler managedLoginRequestHandler;
    private final TrafficUsageService trafficUsageService;
    private final TrafficInspectionService trafficInspectionService;
    private final RemotePortServerManager remotePortServerManager;
    private final TlsProperties tlsProperties;
    private final WebSocketStreamRegistry webSocketStreamRegistry;
    private final WebSocketSpecusHandler webSocketSpecusHandler;
    private final ServerMessageHandler serverMessageHandler;
    private final ControlProtocolMetricsHandler controlProtocolMetricsHandler;
    private final Environment environment;
    private final Counter plaintextDeploymentRejected;
    private final AtomicLong certificateExpiryEpochSeconds = new AtomicLong();
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel channel;

    public NettyServer(NettyServerProperties nettyProperties,
                       ManagedLoginRequestHandler managedLoginRequestHandler,
                       TrafficUsageService trafficUsageService,
                       TrafficInspectionService trafficInspectionService,
                       RemotePortServerManager remotePortServerManager,
                       TlsProperties tlsProperties,
                       WebSocketStreamRegistry webSocketStreamRegistry,
                       WebSocketSpecusHandler webSocketSpecusHandler,
                       ServerMessageHandler serverMessageHandler,
                       ControlProtocolMetricsHandler controlProtocolMetricsHandler,
                       Environment environment,
                       io.micrometer.core.instrument.MeterRegistry meterRegistry) {
        this.nettyProperties = nettyProperties;
        this.managedLoginRequestHandler = managedLoginRequestHandler;
        this.trafficUsageService = trafficUsageService;
        this.trafficInspectionService = trafficInspectionService;
        this.remotePortServerManager = remotePortServerManager;
        this.tlsProperties = tlsProperties;
        this.webSocketStreamRegistry = webSocketStreamRegistry;
        this.webSocketSpecusHandler = webSocketSpecusHandler;
        this.serverMessageHandler = serverMessageHandler;
        this.controlProtocolMetricsHandler = controlProtocolMetricsHandler;
        this.environment = environment;
        this.plaintextDeploymentRejected = Counter.builder("specus.control.plaintext.deployment.rejected")
                .register(meterRegistry);
        Gauge.builder("specus.control.tls.certificate.expiry.epoch.seconds", certificateExpiryEpochSeconds, AtomicLong::get)
                .register(meterRegistry);
        Gauge.builder("specus.control.tls.mode", () -> 1.0D)
                .tag("mode", effectiveTlsMode())
                .strongReference(true)
                .register(meterRegistry);
    }

    @Override
    public void run(ApplicationArguments args) {
        start();
    }

    public void start() {
        validateConfiguration();
        bossGroup = newEventLoopGroup(nettyProperties.getBossThreads());
        workerGroup = newEventLoopGroup(nettyProperties.getWorkerThreads());

        // Build the TLS context once, at startup. If TLS is disabled this is null
        // and we leave the pipeline plain.
        final SslContext sslContext = TlsContextFactory.buildServerContext(
                tlsProperties.resolveMode(),
                tlsProperties.getKeystore(),
                tlsProperties.getKeystorePassword(),
                tlsProperties.getKeyPassword()
        );
        if (sslContext != null) {
            log.info("[tls] control channel is encrypted (mode={})", tlsProperties.getMode());
            if (tlsProperties.resolveMode() == TlsContextFactory.Mode.FILE) {
                certificateExpiryEpochSeconds.set(TlsContextFactory.certificateExpiryEpochSeconds(
                        tlsProperties.getKeystore(), tlsProperties.getKeystorePassword()));
            }
        } else {
            log.warn("[tls] control channel is PLAIN (TLS disabled, upstreamTermination={})",
                    tlsProperties.isTerminatedUpstream());
        }

        final ServerBootstrap serverBootstrap = new ServerBootstrap();
        WriteBufferWaterMark waterMark = nettyProperties.writeBufferWaterMark();
        serverBootstrap
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, nettyProperties.getSoBacklog())
                .option(ChannelOption.SO_REUSEADDR, nettyProperties.isReuseAddress())
                .childOption(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                .childOption(ChannelOption.SO_KEEPALIVE, nettyProperties.isKeepAlive())
                .childOption(ChannelOption.TCP_NODELAY, nettyProperties.isTcpNoDelay())
                .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, waterMark)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) throws Exception {
                        if (sslContext != null) {
                            SslHandler sslHandler = sslContext.newHandler(ch.alloc());
                            // startTls=true: avoid wasting bandwidth on a TLS handshake
                            // until the client says hello, which also means plaintext
                            // HTTP probes (health checks) don't trip the SSL state
                            // machine.
                            ch.pipeline().addFirst(sslHandler);
                        }
                        ch.pipeline().addLast(new SocketIdleStateHandler());
                        ch.pipeline().addLast(
                                Spliter.PRE_AUTH_HANDLER_NAME,
                                new Spliter(nettyProperties.getPreAuthMaxFrameSize()));
                        ch.pipeline().addLast(PacketCodecHandler.INSTANCE);
                        ch.pipeline().addLast(controlProtocolMetricsHandler);
                        ch.pipeline().addLast(managedLoginRequestHandler);
                        ch.pipeline().addLast(AuthHandler.INSTANCE);
                        ch.pipeline().addLast(ConnectionRoleHandler.INSTANCE);
                        ch.pipeline().addLast(HeartbeatRequestHandler.INSTANCE);
                        ch.pipeline().addLast(new NatServerHandler(
                                trafficUsageService,
                                trafficInspectionService,
                                remotePortServerManager,
                                nettyProperties,
                                webSocketStreamRegistry,
                                webSocketSpecusHandler
                        ));
                        ch.pipeline().addLast(serverMessageHandler);
                        ch.pipeline().addLast(LogoutRequestHandler.INSTANCE);
                    }
                });
        bind(serverBootstrap);
    }

    private void bind(final ServerBootstrap serverBootstrap) {
        int port = nettyProperties.getPort();
        ChannelFuture channelFuture = serverBootstrap.bind(nettyProperties.getBindAddress(), port);
        channelFuture.addListener((ChannelFuture future) -> {
            if (future.isSuccess()) {
                channel = future.channel();
                log.info("端口[{}] 绑定成功!", port);
            } else {
                log.error("端口[{}] 绑定失败: {}", port, future.cause().toString());
            }
        });
    }

    @PreDestroy
    public void stop() {
        if (channel != null) {
            channel.close();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
    }

    /**
     * Actual TCP port the server is listening on. Useful for tests that bind
     * with port=0 and need to discover the kernel-assigned port.
     */
    public int getBoundPort() {
        if (channel == null) {
            return -1;
        }
        java.net.SocketAddress address = channel.localAddress();
        if (address instanceof java.net.InetSocketAddress isa) {
            return isa.getPort();
        }
        return -1;
    }

    private EventLoopGroup newEventLoopGroup(int threads) {
        if (threads > 0) {
            return new MultiThreadIoEventLoopGroup(threads, NioIoHandler.newFactory());
        }
        return new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
    }

    private void validateConfiguration() {
        if (nettyProperties.getPreAuthMaxFrameSize() < com.theshuai.common.protocol.PacketCodec.HEADER_SIZE
                || nettyProperties.getPreAuthMaxFrameSize() > nettyProperties.getMaxFrameSize()) {
            throw new IllegalStateException("pre-auth frame size must be between the protocol header and max frame size");
        }
        boolean production = tlsProperties.isRequireEncryption()
                || Arrays.stream(environment.getActiveProfiles())
                .anyMatch(profile -> profile.equalsIgnoreCase("prod") || profile.equalsIgnoreCase("production"));
        if (!production) {
            return;
        }
        TlsContextFactory.Mode mode = tlsProperties.resolveMode();
        if (mode == TlsContextFactory.Mode.SELF_SIGNED) {
            plaintextDeploymentRejected.increment();
            throw new IllegalStateException("production control channel cannot use a self-signed certificate");
        }
        if (mode == TlsContextFactory.Mode.DISABLED
                && (!tlsProperties.isTerminatedUpstream() || !isPrivateBindAddress(nettyProperties.getBindAddress()))) {
            plaintextDeploymentRejected.increment();
            throw new IllegalStateException(
                    "production control channel requires TLS, or trusted upstream TLS with a private/loopback bind address");
        }
    }

    private String effectiveTlsMode() {
        if (tlsProperties.resolveMode() != TlsContextFactory.Mode.DISABLED) {
            return tlsProperties.resolveMode().name().toLowerCase();
        }
        return tlsProperties.isTerminatedUpstream() ? "terminated_upstream" : "disabled";
    }

    private boolean isPrivateBindAddress(String value) {
        try {
            InetAddress address = InetAddress.getByName(value);
            return !address.isAnyLocalAddress()
                    && (address.isLoopbackAddress() || address.isSiteLocalAddress() || address.isLinkLocalAddress());
        } catch (Exception e) {
            return false;
        }
    }
}
