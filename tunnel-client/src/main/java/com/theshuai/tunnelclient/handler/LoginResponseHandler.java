package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.response.LoginResponsePacket;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoginResponseHandler extends SimpleChannelInboundHandler<LoginResponsePacket> {

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, LoginResponsePacket loginResponsePacket) throws Exception {
        String clientName = loginResponsePacket.getClientName();
        if (loginResponsePacket.isSuccess()) {
            log.info("[{}]登录成功", clientName);
            // Do NOT touch SessionUtil here. SessionUtil.clientChannelMap is the
            // server-side routing table. Server-side ManagedLoginRequestHandler
            // already calls bindSession on the same channel; if the client also
            // calls bindSession, the resulting ConcurrentHashMap.put() sees a
            // non-null old channel, closes it, and tears down the connection
            // we are literally trying to use.
        } else {
            log.info("[{}]登录失败,原因:{}", clientName, loginResponsePacket.getReason());
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("客户端连接被关闭");
        // Do NOT unbind either — see the comment in channelRead0.
    }
}
