package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.tunnelclient.client.NettyClient;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.TimeUnit;

@Slf4j
public class ClientSocketIdleStateHandler extends IdleStateHandler {
    private static final int READER_IDLE_TIME = 60;
    /**
     * 5 秒写空闲就发心跳——既是探活，也是保 NAT/防火墙连接表。
     *
     * <p>实现选 {@code IdleStateHandler} 而不是单独写 {@code HeartBeatTimerHandler}：
     * <ul>
     *   <li>有真实流量时不会发，只在闲置时触发，省流量。</li>
     *   <li>从 {@code channelIdle} 回调里 {@code ctx.writeAndFlush} 不会回流过自己的 {@code write()}
     *       拦截点，因此心跳本身不会重置 WRITER_IDLE，能稳定每 5 秒发一次。</li>
     * </ul>
     */
    private static final int WRITE_IDLE_TIME = 5;

    private final NettyClient nettyClient;

    public ClientSocketIdleStateHandler(NettyClient nettyClient) {
        super(READER_IDLE_TIME, WRITE_IDLE_TIME, 0, TimeUnit.SECONDS);
        this.nettyClient = nettyClient;
    }

    @Override
    protected void channelIdle(ChannelHandlerContext ctx, IdleStateEvent evt) throws Exception {
        if (evt.state() == IdleState.READER_IDLE) {
            log.info(READER_IDLE_TIME + "秒内未读到数据，关闭连接");
            ctx.close();
        } else if (evt.state() == IdleState.WRITER_IDLE) {
            // 心跳是协议层正常事件，DEBUG 级别即可，避免刷 INFO 日志。
            log.debug("{}秒未写入数据, 发送心跳", WRITE_IDLE_TIME);
            ctx.writeAndFlush(new HeartBeatRequestPacket());
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("控制连接断开, 安排重连...");
        // 让父类 IdleStateHandler 取消内部 reader/writer 计时任务，否则可能在已死的 channel 上残留。
        super.channelInactive(ctx);
        // 走 scheduleReconnect 而不是直接 connect()：保证任何"非首次"的连接都受指数退避节流，
        // 避免对端 flapping 或登录持续失败时蜂拥重连。
        nettyClient.scheduleReconnect();
    }
}
