package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.tunnelclient.client.NettyClient;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoginResponseHandler extends SimpleChannelInboundHandler<LoginResponsePacket> {

    private final NettyClient nettyClient;

    public LoginResponseHandler(NettyClient nettyClient) {
        this.nettyClient = nettyClient;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, LoginResponsePacket loginResponsePacket) throws Exception {
        String clientName = loginResponsePacket.getClientName();
        if (loginResponsePacket.isSuccess()) {
            log.info("[{}]登录成功", clientName);
            // 通知 NettyClient 重置退避计数；TCP 通了不算成功，登录通了才算。
            nettyClient.onLoginSuccess();
            // Do NOT touch SessionUtil here. SessionUtil.clientChannelMap is the
            // server-side routing table. Server-side ManagedLoginRequestHandler
            // already calls bindSession on the same channel; if the client also
            // calls bindSession, the resulting ConcurrentHashMap.put() sees a
            // non-null old channel, closes it, and tears down the connection
            // we are literally trying to use.
        } else {
            log.warn("[{}]登录失败,原因:{} —— 主动关闭连接进入重连退避",
                    clientName, loginResponsePacket.getReason());
            // 关闭 channel 触发 channelInactive → scheduleReconnect。
            // 这里不直接 connect()，让退避计时器把节奏控制住，避免错密码场景蜂拥重连。
            ctx.close();
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("客户端连接被关闭");
        // Do NOT unbind either — see the comment in channelRead0.
    }
}
