package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.common.service.ExecuteService;
import com.theshuai.tunnelclient.bean.HttpTunnelConfig;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DirectHttpRequestHandler extends SimpleChannelInboundHandler<DirectHttpRequestPacket> {
    private final Map<String, String> routes;

    public DirectHttpRequestHandler(List<HttpTunnelConfig> configs) {
        routes = configs == null ? Map.of() : configs.stream()
                .collect(Collectors.toUnmodifiableMap(
                        HttpTunnelConfig::getRoute,
                        HttpTunnelConfig::getTargetBaseUrl,
                        (left, right) -> right
                ));
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DirectHttpRequestPacket packet) {
        ExecuteService.submit(() -> ctx.writeAndFlush(DirectHttpForwarder.forward(packet, routes)));
    }
}
