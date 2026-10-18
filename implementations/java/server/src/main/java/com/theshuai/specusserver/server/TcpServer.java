package com.theshuai.specusserver.server;

import com.theshuai.specusserver.config.NettyServerProperties;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;

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
                .childOption(ChannelOption.ALLOW_HALF_CLOSURE, true)
                .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, waterMark);
        var binding = bootstrap.bind(port);
        channel = binding.channel(); // Retain ownership even if the blocking bind is interrupted.
        try {
            binding.sync();
        } catch (InterruptedException | RuntimeException failure) {
            // bind() must not report failure while its listener can still occupy the port.
            channel.close().syncUninterruptibly();
            throw failure;
        }
    }

    public synchronized void close() {
        closeAsync();
    }

    public synchronized CompletableFuture<Void> closeAsync() {
        var closed = new CompletableFuture<Void>();
        if (channel != null) {
            channel.close().addListener(result -> {
                if(result.isSuccess()) closed.complete(null);
                else closed.completeExceptionally(result.cause());
            });
        } else closed.complete(null);
        return closed;
    }

    synchronized int localPort() {
        if (channel == null || !(channel.localAddress() instanceof InetSocketAddress address)) {
            throw new IllegalStateException("TCP server is not bound");
        }
        return address.getPort();
    }
}
