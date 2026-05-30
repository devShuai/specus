package com.theshuai.common.handler;

import com.theshuai.common.protocol.request.HttpRequestPacket;
import com.theshuai.common.protocol.response.HttpResponsePacket;
import com.theshuai.common.util.HttpUtil;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

@ChannelHandler.Sharable
@Slf4j
public class CustomHttpRequestHandler extends SimpleChannelInboundHandler<HttpRequestPacket> {

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, HttpRequestPacket httpRequestPacket) throws Exception {
        HttpResponsePacket httpResponsePacket = new HttpResponsePacket();
        httpResponsePacket.setClientName(httpRequestPacket.getClientName());
        httpResponsePacket.setToClientName(httpRequestPacket.getToClientName());
        httpResponsePacket.setRequestId(httpRequestPacket.getRequestId());
        try {
            String result = HttpUtil.sendRequest(httpRequestPacket.getRequestMethod(), httpRequestPacket.getRequestUrl(), httpRequestPacket.getParamMap(), httpRequestPacket.getHeaderMap(), httpRequestPacket.getBody());
            httpResponsePacket.setResponse(result);
            log.info("request result: {}", result);
            ctx.channel().writeAndFlush(httpResponsePacket).addListener(future -> {
                if (future.isDone()) {
                    log.info("发送结束");
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            log.info("send request exception");
        }
    }
}
