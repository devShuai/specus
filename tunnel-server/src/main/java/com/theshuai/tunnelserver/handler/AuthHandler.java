package com.theshuai.tunnelserver.handler;

import com.theshuai.tunnelserver.session.SessionUtil;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

/**
 * 控制连接的入站鉴权门：未登录的连接收到任何 packet 都会被关闭。登录成功后从 pipeline 移除自己。
 *
 * <p>从 tunnel-common 迁来，因为它依赖 {@link SessionUtil}（服务端 only 状态）。
 */
@ChannelHandler.Sharable
public class AuthHandler extends ChannelInboundHandlerAdapter {
    public static final AuthHandler INSTANCE = new AuthHandler();

    private AuthHandler() {
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!SessionUtil.hasLogin(ctx.channel())) {
            ctx.channel().close();
        } else {
            ctx.pipeline().remove(this);
            super.channelRead(ctx, msg);
        }
    }
}
