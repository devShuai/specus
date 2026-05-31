package com.theshuai.tunnelserver.server;


import com.theshuai.common.codec.PacketCodecHandler;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.handler.*;
import com.theshuai.tunnelserver.handler.ManagedLoginRequestHandler;
import com.theshuai.tunnelserver.handler.NatServerHandler;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class NettyServer implements ApplicationRunner {
    private final int port;
    private final ManagedLoginRequestHandler managedLoginRequestHandler;
    private final TrafficUsageService trafficUsageService;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel channel;

    public NettyServer(@Value("${tunnel.netty.port:7010}") int port,
                       ManagedLoginRequestHandler managedLoginRequestHandler,
                       TrafficUsageService trafficUsageService) {
        this.port = port;
        this.managedLoginRequestHandler = managedLoginRequestHandler;
        this.trafficUsageService = trafficUsageService;
    }

    @Override
    public void run(ApplicationArguments args) {
        start();
    }

    public void start() {
        bossGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        workerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());

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
        serverBootstrap.bind(port).addListener(future -> {
            if (future.isSuccess()) {
                channel = ((io.netty.channel.ChannelFuture) future).channel();
                System.out.println(new Date() + ": 端口[" + port + "] 绑定成功!");
            } else {
                System.out.println("端口[" + port + "]绑定失败!");
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
}
