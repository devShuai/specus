package com.theshuai.common.service;

import com.theshuai.common.future.SyncFuture;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.HttpRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.util.SessionUtil;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
public class GatewayService {
    public static String sendMessage(String clientName, String message) {
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel != null) {
            MessageResponsePacket messageResponsePacket = new MessageResponsePacket();
            messageResponsePacket.setClientName("system");
            messageResponsePacket.setToClientName(clientName);
            messageResponsePacket.setMessageType(MessageType.SERVER_TO_CLIENT);
            messageResponsePacket.setMessage(message);
            channel.writeAndFlush(messageResponsePacket);
            log.info("send message: [{}] success to clientName:{}", message, clientName);
            return "发送成功";
        }

        return "找不到对应的clientName [" + clientName + "]";
    }

    public static String sendHttpSyncMessage(String clientName,
                                             String requestId,
                                             String url,
                                             String method,
                                             Map<String, String> paramMap,
                                             Map<String, String> headerMap,
                                             String body,
                                             SyncFuture<String> syncFuture) {
        String result = null;
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel != null) {
            HttpRequestPacket httpRequestPacket = new HttpRequestPacket();
            httpRequestPacket.setClientName("system");
            httpRequestPacket.setRequestUrl(url);
            httpRequestPacket.setToClientName(clientName);
            httpRequestPacket.setRequestId(requestId);
            httpRequestPacket.setRequestMethod(method);
            httpRequestPacket.setParamMap(paramMap);
            httpRequestPacket.setHeaderMap(headerMap);
            httpRequestPacket.setBody(body);
            log.info("=======> requestId: {}, pre send message: {}", requestId, httpRequestPacket);
            ChannelFuture channelFuture = channel.writeAndFlush(httpRequestPacket);
            try {
                channelFuture.addListener((ChannelFutureListener) future -> {
                    if (future.isSuccess()) {
                        log.info("=======> requestId: {} 发送成功", requestId);
                    } else {
                        syncFuture.setResponse(null);
                        log.info("=======> requestId: {} 发送失败", requestId);
                    }
                });
                result = syncFuture.get(8, TimeUnit.SECONDS);
            } catch (Exception e) {
                log.error("处理失败", e);
            }
        } else {
            syncFuture.setResponse(result);
        }
        return result;
    }
}
