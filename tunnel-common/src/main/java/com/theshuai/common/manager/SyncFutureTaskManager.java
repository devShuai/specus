package com.theshuai.common.manager;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.theshuai.common.future.SyncFuture;
import com.theshuai.common.protocol.response.HttpResponsePacket;
import com.theshuai.common.service.GatewayService;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
public class SyncFutureTaskManager {
    private static final LoadingCache<String, SyncFuture<String>> futureLoadingCache = CacheBuilder.newBuilder()
            .initialCapacity(10)
            .maximumSize(1000)
            .concurrencyLevel(20)
            .expireAfterWrite(8, TimeUnit.SECONDS)
            .removalListener(removalNotification -> log.info("LoadingCache: {} was removed, cause is {}", removalNotification.getKey(), removalNotification.getCause()))
            .build(new CacheLoader<String, SyncFuture<String>>() {
                @Override
                public SyncFuture<String> load(String key) throws Exception {
                    return null;
                }
            });


    public static String sendSyncMsg(String clientName,
                                     String url,
                                     String method,
                                     Map<String, String> paramMap,
                                     Map<String, String> headerMap,
                                     String body) {
        String requestId = UUID.randomUUID().toString();
        SyncFuture<String> syncFuture = new SyncFuture<>();
        // 放入缓存中
        futureLoadingCache.put(requestId, syncFuture);

        // 发送同步消息
        return GatewayService.sendHttpSyncMessage(clientName, requestId, url, method, paramMap, headerMap, body, syncFuture);
    }

    public static void ackSyncMsg(HttpResponsePacket httpResponsePacket) {

        log.info("ACK确认信息: {}", httpResponsePacket);
        String requestId = httpResponsePacket.getRequestId();

        // 从缓存中获取数据
        SyncFuture<String> syncFuture = futureLoadingCache.getIfPresent(requestId);

        // 如果不为null, 则通知返回
        if (syncFuture != null) {
            syncFuture.setResponse(httpResponsePacket.getResponse());
            //主动释放
            futureLoadingCache.invalidate(requestId);
        }
    }

}
