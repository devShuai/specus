package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.request.LogoutRequestPacket;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

/**
 * 接收服务端发来的踢下线消息：直接关闭 channel，触发 channelInactive → 重连退避。
 *
 * <p>原先调 {@code SessionUtil.unBindSession} 是 dead code——客户端从未在 SessionUtil 中
 * bind 过自己（那个 map 是服务端的客户端路由表）。
 */
@Slf4j
public class LogoutResponseHandler extends SimpleChannelInboundHandler<LogoutRequestPacket> {
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, LogoutRequestPacket logoutRequestPacket) throws Exception {
        log.info("收到服务端 logout 指令, 关闭控制连接");
        ctx.close();
    }
}
