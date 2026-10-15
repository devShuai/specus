package com.theshuai.specusserver.session;

import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.management.model.DisconnectReason;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.Objects;
import io.netty.util.AttributeKey;

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
    private static final Map<String, PreparedBinding> preparingControls = new ConcurrentHashMap<>();
    private static final Map<String, PreparedBinding> preparingData = new ConcurrentHashMap<>();
    private static final Map<String, CompletableFuture<Void>> retiringNamespaces = new ConcurrentHashMap<>();
    private static final AttributeKey<DataParent> DATA_PARENT = AttributeKey.valueOf("specus.dataParent");
    private record DataParent(Channel control, Long sessionId) {}
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

    /** Trusted registry-only binding. Network admission must prepare/await/publish below so that
     * old listeners really stop before a successor is visible. */
    public static void bindControlSession(Session session, Channel channel) {
        Channel oldChannel;
        Channel oldData;
        RetirementTicket ticket;
        synchronized (bindingLock(session.getClientName())) {
            preparingControls.remove(session.getClientName());
            preparingData.remove(session.getClientName());
            // Detach the old pair before publishing its successor. Closing the old CONTROL can
            // synchronously accept a new DATA; it must not be removed by a later name-only cleanup.
            oldData = dataChannels.remove(session.getClientName());
            if(oldData != null) oldData.attr(ServerAttributes.SESSION).set(null);
            ticket=oldData == null ? null : reserveRetirement(session.getClientName());
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
            ticket.start(oldData);
        }
    }

    /** Trusted in-process registry binding; no asynchronous resource-retirement wait. */
    public static void bindDataSession(Session session, Channel channel) {
        bindDataSession(session, channel, null, null, false);
    }

    /** Trusted registry-only physical pair binding. Production network admission uses
     * prepareBinding/awaitRetired/publish; reusing an HTTP token never substitutes a new CONTROL. */
    public static boolean bindDataSession(Session session, Channel channel, Channel expectedControl,
                                          Long clientSessionId) {
        return bindDataSession(session, channel, expectedControl, clientSessionId, true);
    }

    private static boolean bindDataSession(Session session, Channel channel, Channel expectedControl,
                                           Long clientSessionId, boolean requireControl) {
        Channel oldChannel;
        RetirementTicket ticket;
        synchronized (bindingLock(session.getClientName())) {
            if (requireControl && (!channel.isActive() || expectedControl == null
                    || matchingControl(session.getClientName(), clientSessionId) != expectedControl)) {
                return false;
            }
            channel.attr(ServerAttributes.SESSION).set(session);
            Channel parent = requireControl ? expectedControl : controlChannels.get(session.getClientName());
            channel.attr(DATA_PARENT).set(new DataParent(parent,
                    requireControl ? clientSessionId : parent == null ? null : parent.attr(ServerAttributes.CLIENT_SESSION_ID).get()));
            preparingData.remove(session.getClientName());
            oldChannel = dataChannels.put(session.getClientName(), channel);
            ticket=oldChannel == null || oldChannel == channel ? null : reserveRetirement(session.getClientName());
            if (oldChannel != null && oldChannel != channel) {
                oldChannel.attr(ServerAttributes.SESSION).set(null);
            }
        }
        channel.closeFuture().addListener(future -> unBindSession(channel));
        if (oldChannel != null && oldChannel != channel) {
            DisconnectReason.markIfAbsent(oldChannel, DisconnectReason.REPLACED_BY_NEW_LOGIN);
            ticket.start(oldChannel);
            log.info("{} 旧数据连接已替换", session.getClientName());
        }
        return true;
    }

    /** Prepare on an admission worker, then await retired() WITHOUT a DB connection or registry
     * lock. Only publish() belongs on the candidate's event loop. A newer attempt invalidates this
     * one, even when it reuses the same HTTP token. */
    public static PreparedBinding prepareBinding(Session session, Channel candidate,
                                                  Channel parent, Long sessionId, boolean data) {
        Channel previousControl = null;
        Channel previousData;
        RetirementTicket ticket;
        PreparedBinding prepared = new PreparedBinding(session, candidate, parent, sessionId, data);
        synchronized (bindingLock(session.getClientName())) {
            if (!candidate.isActive() || (data && (parent == null
                    || matchingControl(session.getClientName(), sessionId) != parent))) return null;
            previousData = dataChannels.remove(session.getClientName());
            if (previousData != null) previousData.attr(ServerAttributes.SESSION).set(null);
            if (!data) {
                previousControl = controlChannels.remove(session.getClientName());
                if (previousControl != null) previousControl.attr(ServerAttributes.SESSION).set(null);
                preparingData.remove(session.getClientName());
            }
            prepared.registry().put(session.getClientName(), prepared);
            ticket=reserveRetirement(session.getClientName());
            prepared.retired=ticket.completion;
        }
        if(previousData != null) DisconnectReason.markIfAbsent(previousData,DisconnectReason.REPLACED_BY_NEW_LOGIN);
        ticket.start(previousData);
        if (previousControl != null && previousControl != candidate) {
            DisconnectReason.markIfAbsent(previousControl, DisconnectReason.REPLACED_BY_NEW_LOGIN);
            previousControl.close();
        }
        return prepared;
    }

    public static final class PreparedBinding implements AutoCloseable {
        private final Session session;
        private final Channel candidate, parent;
        private final Long sessionId;
        private final boolean data;
        private CompletableFuture<Void> retired;
        private boolean published;
        private PreparedBinding(Session session, Channel candidate, Channel parent, Long sessionId, boolean data) {
            this.session=session;this.candidate=candidate;this.parent=parent;this.sessionId=sessionId;this.data=data;
        }
        private Map<String,PreparedBinding> registry() {return data ? preparingData : preparingControls;}
        public CompletableFuture<Void> retired() {return retired;}
        public void awaitRetired() throws Exception {
            for(;;) {
                if(!candidate.isActive()) throw new java.util.concurrent.CancellationException("login channel closed during DATA retirement");
                try {retired.get(25,java.util.concurrent.TimeUnit.MILLISECONDS);return;}
                catch(java.util.concurrent.TimeoutException waiting) { /* No DB connection or registry lock held. */ }
            }
        }
        public boolean publish() {
            synchronized (bindingLock(session.getClientName())) {
                if (!candidate.isActive() || !retired.isDone() || retired.isCompletedExceptionally()
                        || registry().get(session.getClientName()) != this
                        || (data && matchingControl(session.getClientName(), sessionId) != parent)) return false;
                registry().remove(session.getClientName(),this);
                candidate.attr(ServerAttributes.SESSION).set(session);
                if (data) candidate.attr(DATA_PARENT).set(new DataParent(parent,sessionId));
                (data ? dataChannels : controlChannels).put(session.getClientName(),candidate);
                published=true;
            }
            candidate.closeFuture().addListener(future -> unBindSession(candidate));
            return true;
        }
        @Override public void close() {
            boolean close;
            synchronized (bindingLock(session.getClientName())) {
                registry().remove(session.getClientName(),this);close=!published;
            }
            if(close) candidate.close();
        }
    }

    /** Short snapshot, never a CONTROL lifecycle lease and never a lazy reattachment. */
    public static boolean isCurrentData(Channel channel) {
        Session session=getSession(channel);
        if(session == null || !channel.isActive()) return false;
        synchronized(bindingLock(session.getClientName())) {
            DataParent paired=channel.attr(DATA_PARENT).get();
            return dataChannels.get(session.getClientName()) == channel && getSession(channel) == session
                    && paired != null && paired.control != null && paired.control.isActive()
                    && controlChannels.get(session.getClientName()) == paired.control
                    && getSession(paired.control) != null
                    && Objects.equals(paired.sessionId,paired.control.attr(ServerAttributes.CLIENT_SESSION_ID).get());
        }
    }

    private static CompletableFuture<Void> retireAndClose(Channel channel) {
        if(channel == null) return CompletableFuture.completedFuture(null);
        NatServerHandler nat=channel.pipeline().get(NatServerHandler.class);
        CompletableFuture<Void> retired=nat == null ? CompletableFuture.completedFuture(null) : nat.retire();
        retired.whenComplete((ignored,failure) -> channel.close());
        return retired;
    }

    // Reserve under the registry stripe BEFORE detaching becomes observable. Superseding an
    // unpublished attempt must inherit its still-running retirement, not publish past it.
    private static RetirementTicket reserveRetirement(String clientName) {
        return new RetirementTicket(clientName);
    }
    private static final class RetirementTicket {
        final String name;
        final CompletableFuture<Void> completion=new CompletableFuture<>();
        final CompletableFuture<Void> previous;
        RetirementTicket(String name) {this.name=name;previous=retiringNamespaces.put(name,completion);}
        void start(Channel channel) {
            CompletableFuture<Void> current;
            try {current=retireAndClose(channel);}
            catch(RuntimeException failure) {current=CompletableFuture.failedFuture(failure);}
            CompletableFuture.allOf(previous == null ? CompletableFuture.completedFuture(null) : previous,current)
                    .whenComplete((ignored,failure) -> {
                        if(failure == null) {completion.complete(null);retiringNamespaces.remove(name,completion);}
                        else completion.completeExceptionally(failure); // Fail closed while an old listener may still exist.
                    });
        }
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
        RetirementTicket ticket = null;
        synchronized (bindingLock(session.getClientName())) {
            if (controlChannels.remove(session.getClientName(), channel)) {
                oldData = dataChannels.remove(session.getClientName());
                channel.attr(ServerAttributes.DEPARTED_CLIENT).set(session.getClientName());
            }
            boolean removedData=dataChannels.remove(session.getClientName(), channel);
            if(oldData != null || removedData) ticket=reserveRetirement(session.getClientName());
            channel.attr(ServerAttributes.SESSION).set(null);
            channel.attr(ServerAttributes.TENANT_ID).set(null);
        }
        NatServerHandler nat=channel.pipeline().get(NatServerHandler.class);
        if(ticket != null) ticket.start(oldData != null ? oldData : channel);
        else if(nat != null) nat.retire();
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
        RetirementTicket ticket;
        synchronized (bindingLock(clientName)) {
            channel = dataChannels.remove(clientName);
            ticket=channel == null ? null : reserveRetirement(clientName);
            if(channel != null) channel.attr(ServerAttributes.SESSION).set(null);
        }
        if (channel != null) {
            ticket.start(channel);
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
