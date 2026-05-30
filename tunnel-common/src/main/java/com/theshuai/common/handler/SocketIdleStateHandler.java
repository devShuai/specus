package com.theshuai.common.handler;

import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.TimeUnit;

@Slf4j
public class SocketIdleStateHandler extends IdleStateHandler {
    private static final int READER_IDLE_TIME = 60;
    private static final int WRITE_IDLE_TIME = 30;

    public SocketIdleStateHandler() {
        super(READER_IDLE_TIME, 30, 0, TimeUnit.SECONDS);
    }

    @Override
    protected void channelIdle(ChannelHandlerContext ctx, IdleStateEvent evt) throws Exception {
        if (evt.state() == IdleState.READER_IDLE) {
            log.info(READER_IDLE_TIME + "秒内未读到数据，关闭连接");
            ctx.channel().close();
        } else if (evt.state() == IdleState.WRITER_IDLE) {
            log.info("{}秒内未写数据, 发送一个心跳", WRITE_IDLE_TIME);
            HeartBeatResponsePacket heartBeatResponsePacket = new HeartBeatResponsePacket();
            ctx.writeAndFlush(heartBeatResponsePacket);
        }
    }
}
