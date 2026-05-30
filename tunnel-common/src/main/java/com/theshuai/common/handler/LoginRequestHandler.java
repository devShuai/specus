package com.theshuai.common.handler;

import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.SessionUtil;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.springframework.util.DigestUtils;

import java.util.Date;

@ChannelHandler.Sharable
public class LoginRequestHandler extends SimpleChannelInboundHandler<LoginRequestPacket> {

    public static final LoginRequestHandler INSTANCE = new LoginRequestHandler();

    public static final String md5Salt = "May the Force be with you";

    protected LoginRequestHandler() {
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, LoginRequestPacket loginRequestPacket) throws Exception {
        LoginResponsePacket loginResponsePacket = new LoginResponsePacket();
        loginResponsePacket.setVersion(loginRequestPacket.getVersion());
        loginResponsePacket.setClientName(loginRequestPacket.getClientName());

        if (valid(loginRequestPacket)) {
            loginResponsePacket.setSuccess(true);
            System.out.println("[" + loginRequestPacket.getClientName() + "]登录成功");
            SessionUtil.bindSession(new Session(loginRequestPacket.getClientName()), ctx.channel());
        } else {
            loginResponsePacket.setReason("账号密码检验失败");
            loginResponsePacket.setSuccess(false);
            System.out.println(new Date() + ": 登录失败！");
        }

        ctx.writeAndFlush(loginResponsePacket);
    }

    private boolean valid(LoginRequestPacket loginRequestPacket) {

        if (Math.abs(Long.parseLong(loginRequestPacket.getTimestamp()) - System.currentTimeMillis()) > 30 * 1000) {
            return false;
        }
        String signString = md5Salt + loginRequestPacket.getClientName() + loginRequestPacket.getPassword() + loginRequestPacket.getTimestamp();
        return DigestUtils.md5DigestAsHex(signString.getBytes()).equals(loginRequestPacket.getCheckSign());
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        SessionUtil.unBindSession(ctx.channel());
    }
}
