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

/**
 * 客户端 HTTP 路由匹配 + 转发的入口 handler。每条入站
 * {@link DirectHttpRequestPacket} 取 {@code packet.getRoute()} 在 {@link #routes}
 * 表中精确查找 {@code targetBaseUrl}，找不到走 {@code DirectHttpForwarder} 的 502 兜底。
 *
 * <p>路由表生命周期：
 * <ul>
 *   <li>构造期：从客户端本地 {@code tunnelClientConfig.json:httpTunnelConfigList} 读出，
 *       仅作为启动 fallback。</li>
 *   <li>运行期：服务端通过 {@code NAT_CONTROL} 的 {@code httpTunnelConfigList} 字段下发
 *       新版本，{@link MessageResponseHandler} 调用 {@link #applyRoutes} 整体替换。
 *       由于 {@link #routes} 用 {@code volatile} 持有不可变 Map，channelRead0 在
 *       worker 线程读快照时不会撕裂。</li>
 *   <li>{@link #getCurrentRoutes} 仅用于 {@link NatClientHandler#reportHttpRoutes(ChannelHandlerContext)}
 *       回报"客户端实际生效"的路由（可选诊断）。</li>
 * </ul>
 */
@Slf4j
public class DirectHttpRequestHandler extends SimpleChannelInboundHandler<DirectHttpRequestPacket> {
    /**
     * 引用本身 volatile：每次 NAT_CONTROL 推下来都构造一个新 unmodifiable Map 后整体赋值。
     * channelRead0 在 worker 线程拿到的总是某个时刻的完整快照，不会读到半构造态。
     */
    private volatile Map<String, String> routes;

    public DirectHttpRequestHandler(List<HttpTunnelConfig> configs) {
        this.routes = toRouteMap(configs);
    }

    /**
     * 用服务端权威全集替换内存路由表。{@code next == null} 也按"清空"处理（与
     * {@code NAT_CONTROL.httpTunnelConfigList = []} 一致）；调用方在"未接管态"应直接
     * 不调本方法，让客户端继续使用 boot 时的 fallback 表。
     */
    public void applyRoutes(List<HttpTunnelConfig> next) {
        Map<String, String> previous = this.routes;
        Map<String, String> updated = toRouteMap(next);
        this.routes = updated;
        log.info("[http-direct] routes updated: {} -> {} entries", previous.size(), updated.size());
    }

    /** 当前生效的路由快照（不可变）。供 {@link NatClientHandler} 回报上行用。 */
    public Map<String, String> getCurrentRoutes() {
        return routes;
    }

    private static Map<String, String> toRouteMap(List<HttpTunnelConfig> configs) {
        if (configs == null || configs.isEmpty()) {
            return Map.of();
        }
        return configs.stream()
                .filter(c -> c != null && c.getRoute() != null && !c.getRoute().isBlank())
                .collect(Collectors.toUnmodifiableMap(
                        HttpTunnelConfig::getRoute,
                        c -> c.getTargetBaseUrl() == null ? "" : c.getTargetBaseUrl(),
                        (left, right) -> right
                ));
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DirectHttpRequestPacket packet) {
        log.info("[http-direct][client-ingress] requestId={} method={} route={} path={} queryPresent={} bodyBytes={}",
                packet.getRequestId(), packet.getRequestMethod(), packet.getRoute(), packet.getRelativePath(),
                packet.getRawQuery() != null, size(packet.getBody()));
        // 抓取调度时的快照，避免 worker 线程在执行过程中遇到 routes 引用变更而行为不一致
        Map<String, String> snapshot = routes;
        ExecuteService.submit(() -> {
            try {
                writeResponse(ctx, DirectHttpForwarder.forward(packet, snapshot));
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
