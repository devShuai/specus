package com.theshuai.tunnelserver.session;

import com.theshuai.common.session.Session;
import com.theshuai.tunnelserver.attribute.ServerAttributes;
import com.theshuai.tunnelserver.management.model.DisconnectReason;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 服务端的客户端会话路由表：{@code clientName → Channel}。
 *
 * <p>原本叫 {@code com.theshuai.common.util.SessionUtil}——但它的语义全是服务端 only：
 * 客户端从不绑定、从不查询。本次迁移到 tunnel-server，让 tunnel-common 不再混入服务端运行时状态。
 *
 * <p>仍保持为静态门面以最小化调用点 churn；如果将来要引入多实例 / 多租户，
 * 可以把它转成 {@code @Component} 注入。
 */
@Slf4j
public final class SessionUtil {

    private static final Map<String, Channel> clientChannelMap = new ConcurrentHashMap<>();

    private SessionUtil() {
    }

    public static void bindSession(Session session, Channel channel) {
        Channel oldChannel = clientChannelMap.put(session.getClientName(), channel);
        if (oldChannel != null && oldChannel != channel) {
            oldChannel.attr(ServerAttributes.SESSION).set(null);
            // 让 channelInactive 能识别本次关闭是"被新登录替换"，而不是默认的 CLIENT_CLOSED。
            DisconnectReason.markIfAbsent(oldChannel, DisconnectReason.REPLACED_BY_NEW_LOGIN);
            oldChannel.close();
            log.info("{} 旧连接已替换", session.getClientName());
        }
        channel.attr(ServerAttributes.SESSION).set(session);
        channel.closeFuture().addListener(future -> unBindSession(channel));
    }

    public static void unBindSession(Channel channel) {
        Session session = getSession(channel);
        if (session == null) {
            return;
        }
        clientChannelMap.remove(session.getClientName(), channel);
        channel.attr(ServerAttributes.SESSION).set(null);
        channel.attr(ServerAttributes.TENANT_ID).set(null);
        log.info("{} 退出登录", session.getClientName());
    }

    public static Channel getChannel(String clientName) {
        return clientChannelMap.get(clientName);
    }

    public static boolean hasLogin(Channel channel) {
        return getSession(channel) != null;
    }

    public static Session getSession(Channel channel) {
        return channel.attr(ServerAttributes.SESSION).get();
    }
}
