package com.theshuai.specusserver.session;

import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.DisconnectReason;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 服务端的客户端会话路由表：{@code clientName → Channel}。
 *
 * <p>原本叫 {@code com.theshuai.common.util.SessionUtil}——但它的语义全是服务端 only：
 * 客户端从不绑定、从不查询。本次迁移到 specus-server，让 specus-common 不再混入服务端运行时状态。
 *
 * <p>仍保持为静态门面以最小化调用点 churn；如果将来要引入多实例 / 多租户，
 * 可以把它转成 {@code @Component} 注入。
 */
@Slf4j
public final class SessionUtil {

    private static final Map<String, Channel> controlChannels = new ConcurrentHashMap<>();
    private static final Map<String, Channel> dataChannels = new ConcurrentHashMap<>();
    // Bounded, short registry-only locks. Never perform socket I/O, DB work, or wait on a future
    // while holding one: close callbacks may bind a successor on a different event loop.
    private static final Object[] bindingLocks = new Object[256];
    static {
        for (int i = 0; i < bindingLocks.length; i++) bindingLocks[i] = new Object();
    }

    private SessionUtil() {
    }

    public static void bindSession(Session session, Channel channel) {
        bindControlSession(session, channel);
    }

    public static void bindControlSession(Session session, Channel channel) {
        Channel oldChannel;
        Channel oldData;
        synchronized (bindingLock(session.getClientName())) {
            // Detach the old pair before publishing its successor. Closing the old CONTROL can
            // synchronously accept a new DATA; it must not be removed by a later name-only cleanup.
            oldData = dataChannels.remove(session.getClientName());
            channel.attr(ServerAttributes.SESSION).set(session);
            oldChannel = controlChannels.put(session.getClientName(), channel);
            if (oldChannel != null && oldChannel != channel) {
                oldChannel.attr(ServerAttributes.SESSION).set(null);
            }
        }
        channel.closeFuture().addListener(future -> unBindSession(channel));
        if (oldChannel != null && oldChannel != channel) {
            // 让 channelInactive 能识别本次关闭是"被新登录替换"，而不是默认的 CLIENT_CLOSED。
            DisconnectReason.markIfAbsent(oldChannel, DisconnectReason.REPLACED_BY_NEW_LOGIN);
            oldChannel.close();
            log.info("{} 旧连接已替换", session.getClientName());
        }
        if (oldData != null && oldData != channel) {
            DisconnectReason.markIfAbsent(oldData, DisconnectReason.REPLACED_BY_NEW_LOGIN);
            oldData.close();
        }
    }

    /** Trusted in-process binding. Network login must use the physical-CONTROL overload below. */
    public static void bindDataSession(Session session, Channel channel) {
        bindDataSession(session, channel, null, null, false);
    }

    /** Rechecks the exact CONTROL observed after authentication, atomically with DATA publication.
     * Reusing the same HTTP access token does not make two physical CONTROLs interchangeable. */
    public static boolean bindDataSession(Session session, Channel channel, Channel expectedControl,
                                          Long clientSessionId) {
        return bindDataSession(session, channel, expectedControl, clientSessionId, true);
    }

    private static boolean bindDataSession(Session session, Channel channel, Channel expectedControl,
                                           Long clientSessionId, boolean requireControl) {
        Channel oldChannel;
        synchronized (bindingLock(session.getClientName())) {
            if (requireControl && (!channel.isActive() || expectedControl == null
                    || matchingControl(session.getClientName(), clientSessionId) != expectedControl)) {
                return false;
            }
            channel.attr(ServerAttributes.SESSION).set(session);
            oldChannel = dataChannels.put(session.getClientName(), channel);
            if (oldChannel != null && oldChannel != channel) {
                oldChannel.attr(ServerAttributes.SESSION).set(null);
            }
        }
        channel.closeFuture().addListener(future -> unBindSession(channel));
        if (oldChannel != null && oldChannel != channel) {
            DisconnectReason.markIfAbsent(oldChannel, DisconnectReason.REPLACED_BY_NEW_LOGIN);
            oldChannel.close();
            log.info("{} 旧数据连接已替换", session.getClientName());
        }
        return true;
    }

    /**
     * Unbinds a closed or logged-out connection. When it is the client's current control connection,
     * the data connection opened under it is closed too, whoever closed the control connection:
     * the server closing it for a disabled, renamed or deleted client must not leave a data
     * connection bound under that name. This has to happen here: the close-future listener runs
     * before {@code channelInactive} and clears the session attribute handlers would read there,
     * which is also why the departed client is left in {@link ServerAttributes#DEPARTED_CLIENT}.
     * A control connection replaced by a new login lost its session when it was replaced, so its
     * close leaves the new data connection alone and takes no one offline.
     */
    public static void unBindSession(Channel channel) {
        Session session = getSession(channel);
        if (session == null) {
            return;
        }
        Channel oldData = null;
        synchronized (bindingLock(session.getClientName())) {
            if (controlChannels.remove(session.getClientName(), channel)) {
                oldData = dataChannels.remove(session.getClientName());
                channel.attr(ServerAttributes.DEPARTED_CLIENT).set(session.getClientName());
            }
            dataChannels.remove(session.getClientName(), channel);
            channel.attr(ServerAttributes.SESSION).set(null);
            channel.attr(ServerAttributes.TENANT_ID).set(null);
        }
        if (oldData != null) oldData.close();
        log.info("{} 退出登录", session.getClientName());
    }

    public static Channel getChannel(String clientName) {
        return controlChannels.get(clientName);
    }

    public static Channel getDataChannel(String clientName) {
        return dataChannels.get(clientName);
    }

    public static boolean hasMatchingControl(String clientName, Long clientSessionId) {
        return getMatchingControl(clientName, clientSessionId) != null;
    }

    /** A snapshot, not a lease. Callers must recheck it when publishing a dependent DATA. */
    public static Channel getMatchingControl(String clientName, Long clientSessionId) {
        synchronized (bindingLock(clientName)) {
            return matchingControl(clientName, clientSessionId);
        }
    }

    private static Channel matchingControl(String clientName, Long clientSessionId) {
        Channel channel = controlChannels.get(clientName);
        return channel != null
                && channel.isActive()
                && clientSessionId != null
                && clientSessionId.equals(channel.attr(ServerAttributes.CLIENT_SESSION_ID).get())
                ? channel : null;
    }

    public static void closeDataSession(String clientName) {
        Channel channel;
        synchronized (bindingLock(clientName)) {
            channel = dataChannels.remove(clientName);
        }
        if (channel != null) {
            channel.close();
        }
    }

    public static boolean hasLogin(Channel channel) {
        return getSession(channel) != null;
    }

    public static Session getSession(Channel channel) {
        return channel.attr(ServerAttributes.SESSION).get();
    }

    private static Object bindingLock(String clientName) {
        return bindingLocks[(clientName.hashCode() ^ (clientName.hashCode() >>> 16)) & (bindingLocks.length - 1)];
    }
}
