package com.theshuai.tunnelserver.http;

import com.theshuai.common.future.SyncFuture;
import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.tunnelserver.session.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

/**
 * HTTP 直转编排器：管理面板请求 → 写到客户端控制连接 → 等待响应。
 *
 * <p>从原 {@code tunnel-common.manager.DirectHttpFutureManager} 迁来：
 * <ul>
 *   <li>语义本就是服务端 only（依赖 {@link SessionUtil} 路由表，客户端用不到）。</li>
 *   <li>改成 {@link Service @Service} 让 Spring 接管生命周期，单元测试和注入都更直接。</li>
 *   <li>{@link DirectHttpResponseHandler} 把客户端回包转给本类的 {@link #ack(DirectHttpResponsePacket)}。</li>
 * </ul>
 */
@Service
@Slf4j
public class DirectHttpDispatcher {
    private final ConcurrentMap<String, SyncFuture<DirectHttpResponsePacket>> futures = new ConcurrentHashMap<>();

    public DirectHttpResponsePacket forward(String clientName,
                                            DirectHttpRequestPacket packet,
                                            long timeoutMillis) {
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel == null || !channel.isActive()) {
            log.warn("[http-direct][server-dispatch] clientName={} rejected=client-offline", clientName);
            throw new DirectHttpTunnelException(503, "客户端不在线: " + clientName);
        }

        String requestId = UUID.randomUUID().toString();
        packet.setRequestId(requestId);
        long startedAt = System.currentTimeMillis();
        SyncFuture<DirectHttpResponsePacket> future = new SyncFuture<>();
        futures.put(requestId, future);
        try {
            log.info("[http-direct][server->client] requestId={} clientName={} method={} route={} path={} queryPresent={} bodyBytes={} timeoutMs={}",
                    requestId, clientName, packet.getRequestMethod(), packet.getRoute(), packet.getRelativePath(),
                    packet.getRawQuery() != null, size(packet.getBody()), timeoutMillis);
            channel.writeAndFlush(packet).addListener(result -> {
                if (!result.isSuccess()) {
                    log.warn("[http-direct][server->client] requestId={} clientName={} write=failed error={}",
                            requestId, clientName, errorMessage(result.cause()));
                    future.setResponse(failure(requestId, "HTTP 转发请求发送失败"));
                } else {
                    log.info("[http-direct][server->client] requestId={} clientName={} write=success", requestId, clientName);
                }
            });
            DirectHttpResponsePacket response = future.get(timeoutMillis, TimeUnit.MILLISECONDS);
            if (response == null) {
                log.warn("[http-direct][server-wait] requestId={} clientName={} timeoutMs={} elapsedMs={}",
                        requestId, clientName, timeoutMillis, System.currentTimeMillis() - startedAt);
                throw new DirectHttpTunnelException(504, "HTTP 转发请求超时");
            }
            log.info("[http-direct][server-wait] requestId={} clientName={} status={} errorPresent={} bodyBytes={} elapsedMs={}",
                    requestId, clientName, response.getStatusCode(), response.getError() != null,
                    size(response.getBody()), System.currentTimeMillis() - startedAt);
            return response;
        } catch (DirectHttpTunnelException e) {
            throw e;
        } catch (Exception e) {
            log.warn("[http-direct][server-wait] requestId={} clientName={} error={} elapsedMs={}",
                    requestId, clientName, errorMessage(e), System.currentTimeMillis() - startedAt, e);
            throw new DirectHttpTunnelException(502, "HTTP 转发请求失败", e);
        } finally {
            futures.remove(requestId);
        }
    }

    /** 由 {@link DirectHttpResponseHandler} 在收到客户端响应时回调。 */
    public void ack(DirectHttpResponsePacket packet) {
        SyncFuture<DirectHttpResponsePacket> future = futures.get(packet.getRequestId());
        if (future != null) {
            log.info("[http-direct][client->server] requestId={} status={} errorPresent={} bodyBytes={}",
                    packet.getRequestId(), packet.getStatusCode(), packet.getError() != null, size(packet.getBody()));
            future.setResponse(packet);
        } else {
            log.warn("[http-direct][client->server] requestId={} ack=dropped reason=future-not-found status={}",
                    packet.getRequestId(), packet.getStatusCode());
        }
    }

    private static int size(byte[] body) {
        return body == null ? 0 : body.length;
    }

    private static String errorMessage(Throwable error) {
        if (error == null) {
            return "unknown";
        }
        return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
    }

    private static DirectHttpResponsePacket failure(String requestId, String message) {
        DirectHttpResponsePacket packet = new DirectHttpResponsePacket();
        packet.setRequestId(requestId);
        packet.setStatusCode(502);
        packet.setError(message);
        return packet;
    }

    public static class DirectHttpTunnelException extends RuntimeException {
        private final int statusCode;

        public DirectHttpTunnelException(int statusCode, String message) {
            super(message);
            this.statusCode = statusCode;
        }

        public DirectHttpTunnelException(int statusCode, String message, Throwable cause) {
            super(message, cause);
            this.statusCode = statusCode;
        }

        public int getStatusCode() {
            return statusCode;
        }
    }
}
