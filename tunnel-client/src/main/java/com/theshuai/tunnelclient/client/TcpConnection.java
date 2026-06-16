package com.theshuai.tunnelclient.client;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;

public class TcpConnection implements AutoCloseable {
    private static final WriteBufferWaterMark DEFAULT_WRITE_BUFFER_WATER_MARK =
            new WriteBufferWaterMark(32 * 1024, 64 * 1024);

    private final boolean ownsWorkerGroup;
    private volatile EventLoopGroup workerGroup;

    public TcpConnection() {
        this(null, true);
    }

    public TcpConnection(EventLoopGroup workerGroup) {
        this(workerGroup, false);
    }

    private TcpConnection(EventLoopGroup workerGroup, boolean ownsWorkerGroup) {
        this.workerGroup = workerGroup;
        this.ownsWorkerGroup = ownsWorkerGroup;
    }

    public ChannelFuture connect(String host, int port, ChannelInitializer<SocketChannel> channelInitializer) throws InterruptedException {
        EventLoopGroup group = ensureWorkerGroup();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group);
            b.channel(NioSocketChannel.class);
            b.option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT);
            b.option(ChannelOption.SO_KEEPALIVE, true);
            b.option(ChannelOption.TCP_NODELAY, true);
            b.option(ChannelOption.WRITE_BUFFER_WATER_MARK, DEFAULT_WRITE_BUFFER_WATER_MARK);
            b.handler(channelInitializer);

            Channel channel = b.connect(host, port).sync().channel();
            return channel.closeFuture();
        } catch (Exception e) {
            close();
            throw e;
        }
    }

    @Override
    public void close() {
        if (ownsWorkerGroup && workerGroup != null) {
            EventLoopGroup toShutdown = workerGroup;
            workerGroup = null;
            toShutdown.shutdownGracefully();
        }
    }

    private EventLoopGroup ensureWorkerGroup() {
        EventLoopGroup current = workerGroup;
        if (current != null) {
            return current;
        }
        synchronized (this) {
            if (workerGroup == null) {
                workerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
            }
            return workerGroup;
        }
    }
}
