package com.theshuai.specusclient.client;

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

import java.util.concurrent.TimeUnit;

public class TcpConnection implements AutoCloseable {
    private static final WriteBufferWaterMark DEFAULT_WRITE_BUFFER_WATER_MARK =
            new WriteBufferWaterMark(32 * 1024, 64 * 1024);
    static final int CONNECT_TIMEOUT_MILLIS = 5_000;

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

    /**
     * Connects one local stream. A failure belongs to that stream alone: the worker group also
     * carries every other stream's local channel, so it is left running for them.
     */
    public ChannelFuture connect(String host, int port, ChannelInitializer<SocketChannel> channelInitializer) throws InterruptedException {
        EventLoopGroup group = ensureWorkerGroup();
        Bootstrap b = new Bootstrap();
        b.group(group);
        b.channel(NioSocketChannel.class);
        b.option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT);
        // The data connection's loop waits on this connect, so an unreachable target gives up
        // after the same 5 seconds the Go and .NET clients allow, not Netty's 30 second default.
        b.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MILLIS);
        b.option(ChannelOption.SO_KEEPALIVE, true);
        b.option(ChannelOption.TCP_NODELAY, true);
        b.option(ChannelOption.ALLOW_HALF_CLOSURE, true);
        b.option(ChannelOption.WRITE_BUFFER_WATER_MARK, DEFAULT_WRITE_BUFFER_WATER_MARK);
        b.handler(channelInitializer);

        Channel channel = b.connect(host, port).sync().channel();
        return channel.closeFuture();
    }

    @Override
    public void close() {
        if (ownsWorkerGroup && workerGroup != null) {
            EventLoopGroup toShutdown = workerGroup;
            workerGroup = null;
            toShutdown.shutdownGracefully(0, 5, TimeUnit.SECONDS)
                    .awaitUninterruptibly(10, TimeUnit.SECONDS);
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
