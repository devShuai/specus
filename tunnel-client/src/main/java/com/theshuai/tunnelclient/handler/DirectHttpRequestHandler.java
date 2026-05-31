package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.common.service.ExecuteService;
import com.theshuai.tunnelclient.bean.HttpTunnelConfig;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
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
        log.info("[http-direct][client-ingress] requestId={} method={} route={} path={} queryPresent={} bodyBytes={}",
                packet.getRequestId(), packet.getRequestMethod(), packet.getRoute(), packet.getRelativePath(),
                packet.getRawQuery() != null, size(packet.getBody()));
        ExecuteService.submit(() -> {
            try {
                writeResponse(ctx, DirectHttpForwarder.forward(packet, routes));
            } catch (VirtualMachineError error) {
                throw error;
            } catch (Throwable error) {
                log.error("[http-direct][client-worker] requestId={} error={}",
                        packet.getRequestId(), errorMessage(error), error);
                writeResponse(ctx, failure(packet.getRequestId(), errorMessage(error)));
            }
        });
    }

    private void writeResponse(ChannelHandlerContext ctx, DirectHttpResponsePacket response) {
        log.info("[http-direct][client-egress] requestId={} status={} errorPresent={} bodyBytes={}",
                response.getRequestId(), response.getStatusCode(), response.getError() != null, size(response.getBody()));
        ctx.channel().writeAndFlush(response).addListener(result -> {
            if (result.isSuccess()) {
                log.info("[http-direct][client->server] requestId={} write=success status={} errorPresent={} bodyBytes={}",
                        response.getRequestId(), response.getStatusCode(), response.getError() != null,
                        size(response.getBody()));
            } else {
                log.warn("[http-direct][client->server] requestId={} write=failed status={} error={}",
                        response.getRequestId(), response.getStatusCode(), errorMessage(result.cause()));
            }
        });
    }

    private DirectHttpResponsePacket failure(String requestId, String message) {
        DirectHttpResponsePacket response = new DirectHttpResponsePacket();
        response.setRequestId(requestId);
        response.setStatusCode(502);
        response.setError(message);
        return response;
    }

    private int size(byte[] body) {
        return body == null ? 0 : body.length;
    }

    private String errorMessage(Throwable error) {
        if (error == null) {
            return "unknown";
        }
        return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
    }
}
