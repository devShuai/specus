package com.theshuai.tunnelserver.http;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.WebSocketSession;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 浏览器侧 WebSocket 会话注册表：{@code channelId → WebSocketSession}。
 *
 * <p>与 {@code NatServerHandler.externalChannels}（TCP 隧道的公网 socket 注册表）平行存在，
 * 由 {@code NatServerHandler.processData / processDisconnected} 在 TCP 路由前先查这里，
 * 实现按 {@code channelId} 把控制连接上的 {@code DATA / DISCONNECTED} 帧路由到对应的浏览器
 * WS 会话。
 *
 * <p>设计要点：
 * <ul>
 *   <li>独立的 {@link ConcurrentHashMap}，避免和 TCP 隧道的 externalChannels 互相污染。channelId
 *       在 WS 流上由 {@code WebSocketTunnelHandler} 用 UUID 生成，与 Netty {@code Channel.id()}
 *       不会撞，即使撞了也各自只命中自己的 map。</li>
 *   <li>独立 Bean 而不是塞进 {@code NatServerHandler}，是为了让 {@code WebSocketTunnelHandler}
 *       （Spring MVC 8088 端）和 {@code NatServerHandler}（Netty 7010 端）共享同一个实例，
 *       避免循环依赖。</li>
 *   <li>客户端主动关或控制连接断开时，{@link #closeAll()} 兜底关闭所有挂起的浏览器会话。</li>
 * </ul>
 */
@Component
@Slf4j
public class WebSocketStreamRegistry {
    private final Map<String, WebSocketSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, String> sessionClientNames = new ConcurrentHashMap<>();
    private final Map<Integer, String> streamChannels = new ConcurrentHashMap<>();

    public void register(int streamId, String channelId, WebSocketSession session, String clientName) {
        sessions.put(channelId, session);
        sessionClientNames.put(channelId, clientName);
        streamChannels.put(streamId, channelId);
    }

    public WebSocketSession get(String channelId) {
        return sessions.get(channelId);
    }

    public WebSocketSession getByStreamId(int streamId) {
        String channelId = streamChannels.get(streamId);
        return channelId == null ? null : sessions.get(channelId);
    }

    public String channelIdOf(int streamId) {
        return streamChannels.get(streamId);
    }

    public WebSocketSession remove(String channelId) {
        sessionClientNames.remove(channelId);
        streamChannels.entrySet().removeIf(entry -> channelId.equals(entry.getValue()));
        return sessions.remove(channelId);
    }

    public WebSocketSession removeByStreamId(int streamId) {
        String channelId = streamChannels.remove(streamId);
        return channelId == null ? null : remove(channelId);
    }

    public String clientNameOf(String channelId) {
        return sessionClientNames.get(channelId);
    }

    /** 控制连接断开时调用：关闭该客户端所有挂起的浏览器 WS 会话。 */
    public void closeAll(String clientName) {
        for (Map.Entry<String, WebSocketSession> entry : sessions.entrySet()) {
            String channelId = entry.getKey();
            String boundClient = sessionClientNames.get(channelId);
            if (clientName == null || clientName.equals(boundClient)) {
                WebSocketSession session = sessions.remove(channelId);
                sessionClientNames.remove(channelId);
                streamChannels.entrySet().removeIf(stream -> channelId.equals(stream.getValue()));
                if (session != null && session.isOpen()) {
                    try {
                        session.close(CloseStatus.GOING_AWAY);
                    } catch (Exception e) {
                        log.debug("close ws session {} on control disconnect failed: {}",
                                session.getId(), e.toString());
                    }
                }
            }
        }
    }
}
