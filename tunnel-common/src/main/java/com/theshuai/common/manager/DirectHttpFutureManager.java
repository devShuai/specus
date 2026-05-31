package com.theshuai.common.manager;

import com.theshuai.common.future.SyncFuture;
import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.common.util.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

@Slf4j
public final class DirectHttpFutureManager {
    private static final ConcurrentMap<String, SyncFuture<DirectHttpResponsePacket>> FUTURES = new ConcurrentHashMap<>();

    private DirectHttpFutureManager() {
    }

    public static DirectHttpResponsePacket forward(String clientName,
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
        FUTURES.put(requestId, future);
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
            FUTURES.remove(requestId);
        }
    }

    public static void ack(DirectHttpResponsePacket packet) {
        SyncFuture<DirectHttpResponsePacket> future = FUTURES.get(packet.getRequestId());
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
