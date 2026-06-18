package com.theshuai.tunnelclient.handler;

import com.theshuai.common.handler.AbstractIdleHeartbeatHandler;
import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.tunnelclient.client.NettyClient;
import io.netty.channel.ChannelHandlerContext;
import lombok.extern.slf4j.Slf4j;

/**
 * 客户端控制连接的空闲检测：5 秒写空闲发心跳（探活 + 保 NAT 表），60 秒读空闲关连接。
 *
 * <p>断开时走 {@link NettyClient#scheduleReconnect()}，让退避节流而不是直接 connect()，
 * 避免对端 flapping 时蜂拥重连。
 */
@Slf4j
public class ClientSocketIdleStateHandler extends AbstractIdleHeartbeatHandler {
    private static final int READER_IDLE_TIME = 60;
    private static final int WRITE_IDLE_TIME = 5;

    private final NettyClient nettyClient;

    public ClientSocketIdleStateHandler(NettyClient nettyClient) {
        super(READER_IDLE_TIME, WRITE_IDLE_TIME);
        this.nettyClient = nettyClient;
    }

    @Override
    protected Packet buildHeartbeat() {
        return new HeartBeatRequestPacket();
    }

    @Override
    protected void onChannelInactive(ChannelHandlerContext ctx) {
        if (nettyClient.isShuttingDown()) {
            log.debug("控制连接因客户端关闭而断开, 不安排重连");
            return;
        }
        log.info("控制连接断开, 安排重连...");
        nettyClient.scheduleReconnect();
    }
}
