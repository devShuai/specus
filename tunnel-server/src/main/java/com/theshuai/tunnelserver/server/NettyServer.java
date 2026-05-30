package com.theshuai.tunnelserver.server;


import com.theshuai.common.codec.PacketCodecHandler;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.handler.*;
import com.theshuai.tunnelserver.handler.NatServerHandler;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;

import java.util.Date;

public class NettyServer {
    private static final int PORT = 7010;

    public static void start() {
        EventLoopGroup bossGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        EventLoopGroup workerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());

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
                        ch.pipeline().addLast(LoginRequestHandler.INSTANCE);
                        ch.pipeline().addLast(AuthHandler.INSTANCE);
                        ch.pipeline().addLast(HeartbeatRequestHandler.INSTANCE);
                        ch.pipeline().addLast(new NatServerHandler());
                        ch.pipeline().addLast(CustomHttpResponseHandler.INSTANCE);
                        ch.pipeline().addLast(ServerMessageHandler.INSTANCE);
                        ch.pipeline().addLast(LogoutRequestHandler.INSTANCE);
                    }
                });
        bind(serverBootstrap);
    }

    private static void bind(final ServerBootstrap serverBootstrap) {
        serverBootstrap.bind(NettyServer.PORT).addListener(future -> {
            if (future.isSuccess()) {
                System.out.println(new Date() + ": 端口[" + NettyServer.PORT + "] 绑定成功!");
            } else {
                System.out.println("端口[" + NettyServer.PORT + "]绑定失败!");
            }
        });
    }
}
