package com.theshuai.tunnelserver.http;

import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.springframework.stereotype.Component;

/**
 * 接收客户端发回的直转 HTTP 响应，转给 {@link DirectHttpDispatcher#ack} 唤醒等待中的请求。
 *
 * <p>原本静态单例 {@code INSTANCE} 在 tunnel-common；现在由 Spring 管理，避免静态依赖
 * 静态 manager 的链条。{@link ChannelHandler.Sharable} 让一个实例能挂在多条 channel 上。
 */
@Component
@ChannelHandler.Sharable
public class DirectHttpResponseHandler extends SimpleChannelInboundHandler<DirectHttpResponsePacket> {
    private final DirectHttpDispatcher dispatcher;

    public DirectHttpResponseHandler(DirectHttpDispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DirectHttpResponsePacket packet) {
        dispatcher.ack(packet);
    }
}
