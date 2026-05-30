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
    private static final int WRITE_IDLE_TIME = 30;

    private NettyClient nettyClient;

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
            log.info("{}秒未写入数据, 发送心跳", WRITE_IDLE_TIME);
            ctx.writeAndFlush(new HeartBeatRequestPacket());
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("SocketIdleStateHandler 检测到断开, 重连中...");
//        super.channelInactive(ctx);
        ctx.close();
        nettyClient.connect();
    }
}
