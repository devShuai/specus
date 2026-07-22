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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
@Slf4j
public class RemotePortServerManager {
    private final NettyServerProperties properties;
    private final EventLoopGroup bossGroup;
    private final EventLoopGroup workerGroup;
    private final AtomicInteger activeExternalConnections = new AtomicInteger();
    private final LongAdder rejectedExternalConnections = new LongAdder();
    private final ConcurrentMap<String, AtomicInteger> activeExternalConnectionsByTenant = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, LongAdder> rejectedExternalConnectionsByTenant = new ConcurrentHashMap<>();

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
        return tryAcquireExternalConnection("default");
    }

    public boolean tryAcquireExternalConnection(String tenantId) {
        int max = properties.getMaxExternalConnections();
        if (max <= 0) {
            activeExternalConnections.incrementAndGet();
            incrementTenantActive(tenantId);
            return true;
        }
        while (true) {
            int current = activeExternalConnections.get();
            if (current >= max) {
                recordRejectedExternalConnection(tenantId);
                return false;
            }
            if (activeExternalConnections.compareAndSet(current, current + 1)) {
                incrementTenantActive(tenantId);
                return true;
            }
        }
    }

    public void releaseExternalConnection() {
        releaseExternalConnection("default");
    }

    public void releaseExternalConnection(String tenantId) {
        activeExternalConnections.updateAndGet(current -> current > 0 ? current - 1 : 0);
        AtomicInteger tenantCounter = activeExternalConnectionsByTenant.get(tenantId);
        if (tenantCounter != null) {
            decrement(tenantCounter);
        }
    }

    public void recordRejectedExternalConnection() {
        recordRejectedExternalConnection("default");
    }

    public void recordRejectedExternalConnection(String tenantId) {
        rejectedExternalConnections.increment();
        rejectedExternalConnectionsByTenant.computeIfAbsent(tenantId, key -> new LongAdder()).increment();
    }

    public int activeExternalConnections() {
        return activeExternalConnections.get();
    }

    public long rejectedExternalConnections() {
        return rejectedExternalConnections.sum();
    }

    public int activeExternalConnections(String tenantId) {
        AtomicInteger counter = activeExternalConnectionsByTenant.get(tenantId);
        return counter == null ? 0 : counter.get();
    }

    public long rejectedExternalConnections(String tenantId) {
        LongAdder counter = rejectedExternalConnectionsByTenant.get(tenantId);
        return counter == null ? 0 : counter.sum();
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

    private void incrementTenantActive(String tenantId) {
        activeExternalConnectionsByTenant
                .computeIfAbsent(tenantId, key -> new AtomicInteger())
                .incrementAndGet();
    }

    private static int decrement(AtomicInteger counter) {
        return counter.updateAndGet(current -> current > 0 ? current - 1 : 0);
    }
}
