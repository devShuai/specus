package com.theshuai.tunnelserver.server;


import com.theshuai.common.codec.PacketCodecHandler;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.handler.HeartbeatRequestHandler;
import com.theshuai.common.handler.SocketIdleStateHandler;
import com.theshuai.tunnelserver.handler.AuthHandler;
import com.theshuai.tunnelserver.handler.LogoutRequestHandler;
import com.theshuai.tunnelserver.handler.ServerMessageHandler;
import com.theshuai.tunnelserver.config.NettyServerProperties;
import com.theshuai.tunnelserver.handler.ManagedLoginRequestHandler;
import com.theshuai.tunnelserver.handler.NatServerHandler;
import com.theshuai.tunnelserver.management.service.HttpRouteRegistry;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.tunnelserver.security.TlsContextFactory;
import com.theshuai.tunnelserver.security.TlsProperties;
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
import jakarta.annotation.PreDestroy;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class NettyServer implements ApplicationRunner {
    private final NettyServerProperties nettyProperties;
    private final ManagedLoginRequestHandler managedLoginRequestHandler;
    private final TrafficUsageService trafficUsageService;
    private final RemotePortServerManager remotePortServerManager;
    private final TlsProperties tlsProperties;
    private final HttpRouteRegistry httpRouteRegistry;
    private final com.theshuai.tunnelserver.http.DirectHttpResponseHandler directHttpResponseHandler;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel channel;

    public NettyServer(NettyServerProperties nettyProperties,
                       ManagedLoginRequestHandler managedLoginRequestHandler,
                       TrafficUsageService trafficUsageService,
                       RemotePortServerManager remotePortServerManager,
                       TlsProperties tlsProperties,
                       HttpRouteRegistry httpRouteRegistry,
                       com.theshuai.tunnelserver.http.DirectHttpResponseHandler directHttpResponseHandler) {
        this.nettyProperties = nettyProperties;
        this.managedLoginRequestHandler = managedLoginRequestHandler;
        this.trafficUsageService = trafficUsageService;
        this.remotePortServerManager = remotePortServerManager;
        this.tlsProperties = tlsProperties;
        this.httpRouteRegistry = httpRouteRegistry;
        this.directHttpResponseHandler = directHttpResponseHandler;
    }

    @Override
    public void run(ApplicationArguments args) {
        start();
    }

    public void start() {
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
        } else {
            log.info("[tls] control channel is PLAIN (TLS disabled)");
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
                        ch.pipeline().addLast(new Spliter(nettyProperties.getMaxFrameSize()));
                        ch.pipeline().addLast(PacketCodecHandler.INSTANCE);
                        ch.pipeline().addLast(managedLoginRequestHandler);
                        ch.pipeline().addLast(AuthHandler.INSTANCE);
                        ch.pipeline().addLast(HeartbeatRequestHandler.INSTANCE);
                        ch.pipeline().addLast(new NatServerHandler(
                                trafficUsageService,
                                remotePortServerManager,
                                nettyProperties,
                                httpRouteRegistry
                        ));
                        ch.pipeline().addLast(directHttpResponseHandler);
                        ch.pipeline().addLast(ServerMessageHandler.INSTANCE);
                        ch.pipeline().addLast(LogoutRequestHandler.INSTANCE);
                    }
                });
        bind(serverBootstrap);
    }

    private void bind(final ServerBootstrap serverBootstrap) {
        int port = nettyProperties.getPort();
        ChannelFuture channelFuture = serverBootstrap.bind(port);
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
}
