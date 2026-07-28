package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.specusclient.client.NettyClient;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoginResponseHandler extends SimpleChannelInboundHandler<LoginResponsePacket> {

    private final NettyClient nettyClient;
    private final String connectionRole;

    public LoginResponseHandler(NettyClient nettyClient) {
        this(nettyClient, ConnectionRole.CONTROL);
    }

    public LoginResponseHandler(NettyClient nettyClient, String connectionRole) {
        this.nettyClient = nettyClient;
        this.connectionRole = connectionRole;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, LoginResponsePacket loginResponsePacket) throws Exception {
        String clientName = loginResponsePacket.getClientName();
        if (loginResponsePacket.isSuccess()) {
            log.info("[{}]登录成功", clientName);
            // 通知 NettyClient 重置退避计数；TCP 通了不算成功，登录通了才算。
            nettyClient.onLoginSuccess(connectionRole, ctx.channel());
            // Do NOT touch SessionUtil here. SessionUtil.clientChannelMap is the
            // server-side routing table. Server-side ManagedLoginRequestHandler
            // already calls bindSession on the same channel; if the client also
            // calls bindSession, the resulting ConcurrentHashMap.put() sees a
            // non-null old channel, closes it, and tears down the connection
            // we are literally trying to use.
        } else {
            String reason = loginResponsePacket.getReason();
            if (isTokenExpired(reason)) {
                log.warn("[{}]登录失败,原因:{} —— 访问令牌过期，刷新后重连", clientName, reason);
                nettyClient.refreshCredentialsAndReconnect(reason);
            } else if (isRetryable(reason)) {
                log.warn("[{}]登录失败,原因:{} —— 主动关闭连接进入重连退避", clientName, reason);
            } else {
                log.warn("[{}]登录失败,原因:{} —— 认证/策略拒绝，停止重连", clientName, reason);
                nettyClient.stopReconnecting(reason);
            }
            ctx.close();
        }
    }

    private boolean isTokenExpired(String reason) {
        return reason != null && reason.contains("访问令牌已过期");
    }

    private boolean isRetryable(String reason) {
        if (reason == null || reason.isBlank()) {
            return false;
        }
        return reason.contains("服务器繁忙") || reason.contains("连接频率超过限制");
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.info("客户端{}连接被关闭", connectionRole);
        // Do NOT unbind either — see the comment in channelRead0.
    }
}
