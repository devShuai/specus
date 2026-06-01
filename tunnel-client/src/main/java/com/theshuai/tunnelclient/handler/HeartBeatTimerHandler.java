package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.common.util.SessionUtil;
import com.theshuai.tunnelclient.client.NettyClient;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HeartBeatTimerHandler extends ChannelInboundHandlerAdapter {
    private static final int HEARTBEAT_INTERVAL = 5;
    private NettyClient nettyClient;

    public HeartBeatTimerHandler(NettyClient nettyClient) {
        this.nettyClient = nettyClient;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        scheduleSendHeartBeat(ctx);
        super.channelActive(ctx);
    }

    private void scheduleSendHeartBeat(ChannelHandlerContext ctx) {
        ctx.executor().schedule(() -> {
            if (ctx.channel().isActive() && SessionUtil.hasSession(ctx.channel())) {
                ctx.writeAndFlush(new HeartBeatRequestPacket());
                scheduleSendHeartBeat(ctx);
            }
        }, HEARTBEAT_INTERVAL, TimeUnit.SECONDS);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("HeartBeatTimerHandler 检测到断开重连中...");
        nettyClient.connect();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        log.error("Exception caught", cause);
        ctx.close();
    }
}
