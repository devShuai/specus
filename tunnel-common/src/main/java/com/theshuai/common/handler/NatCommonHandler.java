package com.theshuai.common.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class NatCommonHandler extends ChannelInboundHandlerAdapter {

    protected ChannelHandlerContext ctx;

    public ChannelHandlerContext getCtx() {
        return ctx;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        this.ctx = ctx;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        log.info("Exception caught ... ");
        log.error("Exception caught", cause);
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent) {
            IdleStateEvent e = (IdleStateEvent) evt;
            if (e.state() == IdleState.READER_IDLE) {
                log.info("Read idle loss connection.");
                ctx.close();
            } else if (e.state() == IdleState.WRITER_IDLE) {
                NatMessagePacket natMessage = new NatMessagePacket();
                natMessage.setNatMessageType(NatMessageType.KEEPALIVE);
                ctx.writeAndFlush(natMessage);
            }
        }
    }
}
