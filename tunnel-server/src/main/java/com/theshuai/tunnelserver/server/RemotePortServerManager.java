package com.theshuai.tunnelserver.server;

import com.theshuai.tunnelserver.config.NettyServerProperties;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

@Component
@Slf4j
public class RemotePortServerManager {
    private final NettyServerProperties properties;
    private final EventLoopGroup bossGroup;
    private final EventLoopGroup workerGroup;
    private final AtomicInteger activeExternalConnections = new AtomicInteger();
    private final LongAdder rejectedExternalConnections = new LongAdder();

    public RemotePortServerManager(NettyServerProperties properties) {
        this.properties = properties;
        this.bossGroup = newEventLoopGroup(properties.getRemoteBossThreads());
        this.workerGroup = newEventLoopGroup(properties.getRemoteWorkerThreads());
    }

    public TcpServer bind(int port, ChannelInitializer<SocketChannel> channelInitializer) throws InterruptedException {
        TcpServer server = new TcpServer(bossGroup, workerGroup, properties);
        server.bind(port, channelInitializer);
        return server;
    }

    public boolean tryAcquireExternalConnection() {
        int max = properties.getMaxExternalConnections();
        if (max <= 0) {
            activeExternalConnections.incrementAndGet();
            return true;
        }
        while (true) {
            int current = activeExternalConnections.get();
            if (current >= max) {
                recordRejectedExternalConnection();
                return false;
            }
            if (activeExternalConnections.compareAndSet(current, current + 1)) {
                return true;
            }
        }
    }

    public void releaseExternalConnection() {
        activeExternalConnections.updateAndGet(current -> current > 0 ? current - 1 : 0);
    }

    public void recordRejectedExternalConnection() {
        rejectedExternalConnections.increment();
    }

    public int activeExternalConnections() {
        return activeExternalConnections.get();
    }

    public long rejectedExternalConnections() {
        return rejectedExternalConnections.sum();
    }

    @PreDestroy
    public void stop() {
        workerGroup.shutdownGracefully();
        bossGroup.shutdownGracefully();
    }

    private EventLoopGroup newEventLoopGroup(int threads) {
        if (threads > 0) {
            return new MultiThreadIoEventLoopGroup(threads, NioIoHandler.newFactory());
        }
        return new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
    }
}
