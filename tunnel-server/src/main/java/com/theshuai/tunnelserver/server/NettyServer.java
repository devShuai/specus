package com.theshuai.tunnelserver.server;


import com.theshuai.common.codec.PacketCodecHandler;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.handler.*;
import com.theshuai.tunnelserver.handler.ManagedLoginRequestHandler;
import com.theshuai.tunnelserver.handler.NatServerHandler;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.tunnelserver.security.TlsContextFactory;
import com.theshuai.tunnelserver.security.TlsProperties;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.Date;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class NettyServer implements ApplicationRunner {
    private final int port;
    private final ManagedLoginRequestHandler managedLoginRequestHandler;
    private final TrafficUsageService trafficUsageService;
    private final TlsProperties tlsProperties;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel channel;

    public NettyServer(@Value("${tunnel.netty.port:7010}") int port,
                       ManagedLoginRequestHandler managedLoginRequestHandler,
                       TrafficUsageService trafficUsageService,
                       TlsProperties tlsProperties) {
        this.port = port;
        this.managedLoginRequestHandler = managedLoginRequestHandler;
        this.trafficUsageService = trafficUsageService;
        this.tlsProperties = tlsProperties;
    }

    @Override
    public void run(ApplicationArguments args) {
        start();
    }

    public void start() {
        bossGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        workerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());

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
        serverBootstrap
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, 1024)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .childOption(ChannelOption.TCP_NODELAY, true)
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
                        ch.pipeline().addLast(new Spliter());
                        ch.pipeline().addLast(PacketCodecHandler.INSTANCE);
                        ch.pipeline().addLast(managedLoginRequestHandler);
                        ch.pipeline().addLast(AuthHandler.INSTANCE);
                        ch.pipeline().addLast(HeartbeatRequestHandler.INSTANCE);
                        ch.pipeline().addLast(new NatServerHandler(trafficUsageService));
                        ch.pipeline().addLast(CustomHttpResponseHandler.INSTANCE);
                        ch.pipeline().addLast(DirectHttpResponseHandler.INSTANCE);
                        ch.pipeline().addLast(ServerMessageHandler.INSTANCE);
                        ch.pipeline().addLast(LogoutRequestHandler.INSTANCE);
                    }
                });
        bind(serverBootstrap);
    }

    private void bind(final ServerBootstrap serverBootstrap) {
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
}
