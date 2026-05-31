package com.theshuai.common.manager;

import com.theshuai.common.future.SyncFuture;
import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.common.util.SessionUtil;
import io.netty.channel.Channel;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public final class DirectHttpFutureManager {
    private static final ConcurrentMap<String, SyncFuture<DirectHttpResponsePacket>> FUTURES = new ConcurrentHashMap<>();

    private DirectHttpFutureManager() {
    }

    public static DirectHttpResponsePacket forward(String clientName,
                                                   DirectHttpRequestPacket packet,
                                                   long timeoutMillis) {
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel == null || !channel.isActive()) {
            throw new DirectHttpTunnelException(503, "客户端不在线: " + clientName);
        }

        String requestId = UUID.randomUUID().toString();
        packet.setRequestId(requestId);
        SyncFuture<DirectHttpResponsePacket> future = new SyncFuture<>();
        FUTURES.put(requestId, future);
        try {
            channel.writeAndFlush(packet).addListener(result -> {
                if (!result.isSuccess()) {
                    future.setResponse(failure(requestId, "HTTP 转发请求发送失败"));
                }
            });
            DirectHttpResponsePacket response = future.get(timeoutMillis, TimeUnit.MILLISECONDS);
            if (response == null) {
                throw new DirectHttpTunnelException(504, "HTTP 转发请求超时");
            }
            return response;
        } catch (DirectHttpTunnelException e) {
            throw e;
        } catch (Exception e) {
            throw new DirectHttpTunnelException(502, "HTTP 转发请求失败", e);
        } finally {
            FUTURES.remove(requestId);
        }
    }

    public static void ack(DirectHttpResponsePacket packet) {
        SyncFuture<DirectHttpResponsePacket> future = FUTURES.get(packet.getRequestId());
        if (future != null) {
            future.setResponse(packet);
        }
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
