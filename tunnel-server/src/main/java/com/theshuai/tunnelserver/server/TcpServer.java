package com.theshuai.tunnelserver.server;

import com.theshuai.tunnelserver.config.NettyServerProperties;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;

public class TcpServer {

    private final EventLoopGroup bossGroup;
    private final EventLoopGroup workerGroup;
    private final NettyServerProperties properties;
    private Channel channel;

    public TcpServer(EventLoopGroup bossGroup, EventLoopGroup workerGroup, NettyServerProperties properties) {
        this.bossGroup = bossGroup;
        this.workerGroup = workerGroup;
        this.properties = properties;
    }

    public synchronized void bind(int port, ChannelInitializer<SocketChannel> channelInitializer) throws InterruptedException {
        WriteBufferWaterMark waterMark = properties.writeBufferWaterMark();
        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, properties.getSoBacklog())
                .option(ChannelOption.SO_REUSEADDR, properties.isReuseAddress())
                .childHandler(channelInitializer)
                .childOption(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                .childOption(ChannelOption.SO_KEEPALIVE, properties.isKeepAlive())
                .childOption(ChannelOption.TCP_NODELAY, properties.isTcpNoDelay())
                .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, waterMark);
        channel = bootstrap.bind(port).sync().channel();
    }

    public synchronized void close() {
        if (channel != null) {
            channel.close();
        }
    }
}
