package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.SessionUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoginResponseHandler extends SimpleChannelInboundHandler<LoginResponsePacket> {

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, LoginResponsePacket loginResponsePacket) throws Exception {
        String clientName = loginResponsePacket.getClientName();
        if (loginResponsePacket.isSuccess()) {
            System.out.println("[" + clientName + "]登录成功");
            SessionUtil.bindSession(new Session(clientName), ctx.channel());
        } else {
            System.out.println("[" + clientName + "]登录失败,原因:" + loginResponsePacket.getReason());
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("客户端连接被关闭");
        SessionUtil.unBindSession(ctx.channel());
    }
}
