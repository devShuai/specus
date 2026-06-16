package com.theshuai.tunnelserver.config;

import io.netty.channel.WriteBufferWaterMark;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "tunnel.netty")
@Data
public class NettyServerProperties {
    private int port = 7010;
    private int bossThreads = 1;
    private int workerThreads = 0;
    private int remoteBossThreads = 1;
    private int remoteWorkerThreads = 0;
    private int soBacklog = 8192;
    private boolean reuseAddress = true;
    private boolean keepAlive = true;
    private boolean tcpNoDelay = true;
    private int writeBufferLowWaterMark = 32 * 1024;
    private int writeBufferHighWaterMark = 64 * 1024;
    private int maxFrameSize = 32 * 1024 * 1024;
    private int maxExternalConnections = 10_000;
    private int maxExternalConnectionsPerClient = 10_000;
    private int maxExternalConnectionsPerPort = 10_000;

    public WriteBufferWaterMark writeBufferWaterMark() {
        int low = Math.max(1, writeBufferLowWaterMark);
        int high = Math.max(low + 1, writeBufferHighWaterMark);
        return new WriteBufferWaterMark(low, high);
    }
}
