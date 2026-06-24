package com.theshuai.common.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.SocketException;
import java.util.Locale;

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
        if (isPeerDisconnect(cause)) {
            log.info("Peer closed connection: {}", exceptionSummary(cause));
        } else {
            log.error("Exception caught", cause);
        }
        ctx.close();
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

    private boolean isPeerDisconnect(Throwable cause) {
        for (Throwable current = cause; current != null; current = current.getCause()) {
            if (!(current instanceof SocketException) && !(current instanceof IOException)) {
                continue;
            }
            String message = current.getMessage();
            if (message == null) {
                continue;
            }
            String normalized = message.toLowerCase(Locale.ROOT);
            if (normalized.contains("connection reset")
                    || normalized.contains("broken pipe")
                    || normalized.contains("forcibly closed")
                    || normalized.contains("远程主机强迫关闭")
                    || normalized.contains("你的主机中的软件中止")) {
                return true;
            }
        }
        return false;
    }

    private String exceptionSummary(Throwable cause) {
        if (cause == null) {
            return "unknown";
        }
        String message = cause.getMessage();
        return cause.getClass().getSimpleName() + (message == null || message.isBlank() ? "" : ": " + message);
    }
}
