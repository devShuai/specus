package com.theshuai.tunnelclient.client;

import com.theshuai.common.codec.PacketDecoder;
import com.theshuai.common.codec.PacketEncoder;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.handler.*;
import com.theshuai.tunnelclient.peer.PeerMeshClient;
import com.theshuai.tunnelclient.peer.PeerVirtualDeviceOptions;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.*;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.ScheduledFuture;

import java.io.File;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLException;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

/**
 * 控制连接的 Netty 客户端：负责建立 TCP 连接、token 登录、断线后指数退避重连。
 *
 * <p>重连状态机要点：
 * <ul>
 *   <li>{@link #reconnectAttempts} 仅在 <b>登录成功</b>后重置为 0；TCP 三次握手成功不算数，
 *       避免凭证错误等场景导致退避失效。</li>
 *   <li>{@link #reconnectScheduled} 互斥多路径同时调度（{@code channelInactive} 与延时任务），
 *       保证任意时刻最多一次在飞的重连。</li>
 *   <li>{@link #shuttingDown} 一旦置位，任何重连都被吞掉，避免 {@code shutdown()} 后日志/异常噪声。</li>
 *   <li>没有重连次数上限——隧道客户端语义就是"一直尝试自愈"，退避封顶 60s。</li>
 * </ul>
 */
@Slf4j
public class NettyClient {
    @Getter
    private volatile String clientName;
    private volatile String accessToken;
    private volatile Long clientSessionId;
    private volatile long tokenTtlSeconds;
    private volatile long tokenExpiresAtMillis;
    private volatile String host;
    private volatile int port;
    private final TunnelBean tunnelBean;
    private final Bootstrap bootstrap = new Bootstrap();
    private final AtomicInteger reconnectAttempts = new AtomicInteger(0);
    private final AtomicBoolean reconnectScheduled = new AtomicBoolean(false);
    private final AtomicBoolean shuttingDown = new AtomicBoolean(false);
    private final AtomicBoolean reconnectSuppressed = new AtomicBoolean(false);
    private final AtomicBoolean authRefreshInProgress = new AtomicBoolean(false);
    private final AtomicReference<ScheduledFuture<?>> proactiveRefreshFuture = new AtomicReference<>();
    private volatile EventLoopGroup workerGroup;
    private volatile EventLoopGroup localWorkerGroup;
    private volatile TcpConnection localConnection;
    private final SslContext sslContext;
    private final AtomicReference<Channel> controlChannel = new AtomicReference<>();
    private final PeerMeshClient peerMeshClient;

    /** 退避上限：连续 5 次失败后稳定到一分钟一次，长期网络故障可自愈。 */
    private static final int MAX_RECONNECT_DELAY_SECONDS = 60;
    private static final long BASE_RECONNECT_DELAY_SECONDS = 2L;
    private static final long PROACTIVE_REFRESH_MAX_LEAD_SECONDS = 300L;
    private static final long PROACTIVE_REFRESH_MIN_LEAD_SECONDS = 30L;
    private static final long PROACTIVE_REFRESH_MIN_DELAY_SECONDS = 5L;
    private static final long PROACTIVE_REFRESH_RETRY_DELAY_SECONDS = 60L;

    public NettyClient(TunnelBean tunnelBean) {
        this(tunnelBean, null);
    }

    public NettyClient(TunnelBean tunnelBean, SslContext sslContext) {
        this.tunnelBean = tunnelBean;
        this.clientName = tunnelBean.getClientName();
        this.accessToken = tunnelBean.getAccessToken();
        this.clientSessionId = tunnelBean.getClientSessionId();
        this.tokenTtlSeconds = tunnelBean.getTokenTtlSeconds();
        this.tokenExpiresAtMillis = tunnelBean.getTokenExpiresAtMillis();
        if (!StringUtils.hasText(accessToken) || clientSessionId == null || clientSessionId <= 0) {
            throw new IllegalStateException("Tunnel client must login through HTTP first and receive accessToken/clientSessionId");
        }
        this.host = tunnelBean.getRemoteAddress();
        this.port = tunnelBean.getRemotePort();
        this.sslContext = sslContext;
        PeerVirtualDeviceOptions peerOptions = new PeerVirtualDeviceOptions(
                tunnelBean.getPeerMeshDevice(),
                tunnelBean.getPeerMeshTunName(),
                tunnelBean.getPeerMeshMtu());
        if (tunnelBean.getPeerMeshMtu() != peerOptions.mtu()) {
            log.warn("Peer mesh MTU normalized: configured={}, effective={}, reason=reserve-udp-encapsulation-overhead",
                    tunnelBean.getPeerMeshMtu(), peerOptions.mtu());
        }
        this.peerMeshClient = new PeerMeshClient(tunnelBean.getPeerMesh(), this::sendPeerControl, peerOptions);
    }

    public void start() {
        if (workerGroup == null) {
            workerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        }
        if (localWorkerGroup == null) {
            localWorkerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        }
        if (localConnection == null) {
            localConnection = new TcpConnection(localWorkerGroup);
        }
        scheduleProactiveRefresh();
        TcpConnection sharedLocalConnection = localConnection;
        bootstrap.group(workerGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(32 * 1024, 64 * 1024))
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    public void initChannel(SocketChannel ch) {
                        if (sslContext != null) {
                            SslHandler sslHandler = sslContext.newHandler(ch.alloc(), host, port);
                            ch.pipeline().addFirst(sslHandler);
                        }
                        ch.pipeline().addLast(new ClientSocketIdleStateHandler(NettyClient.this));
                        ch.pipeline().addLast(new Spliter());
                        ch.pipeline().addLast(new PacketDecoder());
                        ch.pipeline().addLast(new LoginResponseHandler(NettyClient.this));
                        ch.pipeline().addLast(new MessageResponseHandler(sharedLocalConnection, peerMeshClient));
                        ch.pipeline().addLast(new DirectHttpRequestHandler(tunnelBean.getHttpTunnelConfigList()));
                        ch.pipeline().addLast(new LogoutResponseHandler());
                        ch.pipeline().addLast(new PacketEncoder());
                        // 心跳由 ClientSocketIdleStateHandler 在 5 秒写空闲时触发，不再需要单独的定时器。
                    }
                });
        connect();
    }

    /**
     * Build a client-side {@link SslContext} that trusts the server certificate
     * stored in {@code truststorePath}. Pass the result to
     * {@link #NettyClient(TunnelBean, SslContext)} to enable TLS.
     */
    public static SslContext buildClientSslContext(String truststorePath, String truststorePassword) {
        try {
            return io.netty.handler.ssl.SslContextBuilder.forClient()
                    .trustManager(new File(truststorePath))
                    .build();
        } catch (SSLException e) {
            throw new IllegalStateException("Failed to build client SslContext: " + e.getMessage(), e);
        }
    }

    /**
     * Build a client-side {@link SslContext} that accepts every server
     * certificate. Dev/test use only.
     */
    public static SslContext buildInsecureClientSslContext() {
        try {
            return io.netty.handler.ssl.SslContextBuilder.forClient()
                    .trustManager(io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                    .build();
        } catch (SSLException e) {
            throw new IllegalStateException("Failed to build insecure client SslContext: " + e.getMessage(), e);
        }
    }

    /**
     * 发起一次连接尝试。可由 {@link #start()}、{@link ClientSocketIdleStateHandler#channelInactive}
     * 或 {@link #scheduleReconnect()} 的延时任务调用；调用方不需要互斥，本方法自身是幂等的：
     * <ul>
     *   <li>{@link #shuttingDown} 置位时直接返回。</li>
     *   <li>TCP 失败则进入退避；TCP 成功只发送登录请求，<b>不重置</b>退避计数。</li>
     * </ul>
     */
    public void connect() {
        if (shouldStopConnecting()) return;
        String connectHost = host;
        int connectPort = port;
        bootstrap.connect(connectHost, connectPort).addListener((ChannelFutureListener) future -> {
            if (shouldStopConnecting()) {
                if (future.isSuccess()) future.channel().close();
                return;
            }
            if (future.isSuccess()) {
                Channel channel = future.channel();
                Channel previous = controlChannel.getAndSet(channel);
                if (previous != null && previous != channel && previous.isOpen()) {
                    previous.close();
                }
                channel.closeFuture().addListener(closeFuture -> controlChannel.compareAndSet(channel, null));
                log.info("Connected to {}:{} (awaiting login response)", connectHost, connectPort);
                sendLoginRequest(channel);
            } else {
                log.warn("Connect to {}:{} failed: {}", connectHost, connectPort,
                        future.cause() == null ? "unknown" : future.cause().getMessage());
                scheduleReconnect();
            }
        });
    }

    private void sendLoginRequest(Channel channel) {
        LoginRequestPacket loginRequestPacket = new LoginRequestPacket();
        loginRequestPacket.setClientName(clientName);
        loginRequestPacket.setClientSessionId(clientSessionId);
        loginRequestPacket.setAccessToken(accessToken);
        channel.writeAndFlush(loginRequestPacket);
    }

    private void sendPeerControl(String toClientName, String message) {
        Channel channel = controlChannel.get();
        if (channel == null || !channel.isActive()) {
            log.debug("Peer mesh 信令暂无法发送: control channel inactive");
            return;
        }
        MessageRequestPacket packet = new MessageRequestPacket();
        packet.setClientName(clientName);
        packet.setToClientName(toClientName);
        packet.setMessageType(MessageType.PEER_CONTROL);
        packet.setMessage(message);
        channel.writeAndFlush(packet).addListener(future -> {
            if (!future.isSuccess()) {
                log.warn("Peer mesh 信令发送失败: {}", future.cause() == null
                        ? "unknown"
                        : future.cause().getMessage());
            }
        });
    }

    /** 由 {@link LoginResponseHandler} 在收到 success=true 时回调，重置退避计数。 */
    public void onLoginSuccess() {
        int prior = reconnectAttempts.getAndSet(0);
        if (prior > 0) {
            log.info("Login succeeded, reconnect backoff reset (was attempt #{})", prior);
        }
        var cachedPeerMesh = tunnelBean.getPeerMesh();
        if (cachedPeerMesh != null && cachedPeerMesh.isEnabled()) {
            peerMeshClient.startOrUpdate(cachedPeerMesh);
        } else if (!peerMeshClient.isRunning()) {
            peerMeshClient.startOrUpdate(cachedPeerMesh);
        } else {
            log.debug("Skip cached disabled peer mesh config after control login; waiting for server runtime config");
        }
    }

    public void stopReconnecting(String reason) {
        reconnectSuppressed.set(true);
        reconnectScheduled.set(false);
        log.warn("Stop reconnecting to {}:{}: {}", host, port,
                StringUtils.hasText(reason) ? reason : "login rejected");
    }

    public void refreshCredentialsAndReconnect(String reason) {
        refreshCredentials(reason, true);
    }

    private void refreshCredentialsWithoutReconnect(String reason) {
        refreshCredentials(reason, false);
    }

    private void refreshCredentials(String reason, boolean reconnectAfterSuccess) {
        if (shouldStopConnecting()) {
            return;
        }
        ClientAuthRefresher refresher = tunnelBean.getAuthRefresher();
        if (refresher == null) {
            log.warn("Cannot refresh client access token: no HTTP login refresher is configured");
            if (reconnectAfterSuccess) {
                stopReconnecting(reason);
            }
            return;
        }
        if (!authRefreshInProgress.compareAndSet(false, true)) {
            log.debug("Client access token refresh is already in progress");
            return;
        }
        reconnectScheduled.set(false);
        CompletableFuture
                .supplyAsync(refresher::refresh)
                .whenComplete((refreshed, error) -> {
                    boolean refreshSucceeded = false;
                    try {
                        if (shuttingDown.get()) {
                            return;
                        }
                        if (error != null) {
                            log.warn("客户端访问令牌刷新失败: {}，稍后重试",
                                    error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage());
                            return;
                        }
                        applyRefreshedTunnelBean(refreshed);
                        refreshSucceeded = true;
                        reconnectAttempts.set(0);
                        log.info("客户端访问令牌刷新成功: clientName={}, session={}, mode={}",
                                clientName, clientSessionId, reconnectAfterSuccess ? "reconnect" : "proactive");
                    } catch (Throwable t) {
                        log.warn("客户端访问令牌刷新结果无效: {}，稍后重试",
                                t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage());
                    } finally {
                        authRefreshInProgress.set(false);
                        if (!shouldStopConnecting()) {
                            if (refreshSucceeded) {
                                scheduleProactiveRefresh();
                            }
                            if (refreshSucceeded && reconnectAfterSuccess) {
                                connect();
                            } else if (!refreshSucceeded && reconnectAfterSuccess) {
                                scheduleReconnect();
                            } else if (!refreshSucceeded) {
                                scheduleProactiveRefreshRetry();
                            }
                        }
                    }
                });
    }

    private void applyRefreshedTunnelBean(TunnelBean refreshed) {
        if (refreshed == null
                || !StringUtils.hasText(refreshed.getAccessToken())
                || refreshed.getClientSessionId() == null
                || refreshed.getClientSessionId() <= 0
                || !StringUtils.hasText(refreshed.getClientName())) {
            throw new IllegalStateException("HTTP login response missing access token/session/clientName");
        }
        if (StringUtils.hasText(refreshed.getRemoteAddress()) && refreshed.getRemotePort() > 0
                && (!refreshed.getRemoteAddress().equals(host) || refreshed.getRemotePort() != port)) {
            log.info("HTTP login returned updated tunnel endpoint {}:{} -> {}:{}",
                    host, port, refreshed.getRemoteAddress(), refreshed.getRemotePort());
            this.host = refreshed.getRemoteAddress();
            this.port = refreshed.getRemotePort();
        }
        this.clientName = refreshed.getClientName();
        this.clientSessionId = refreshed.getClientSessionId();
        this.accessToken = refreshed.getAccessToken();
        this.tokenTtlSeconds = refreshed.getTokenTtlSeconds();
        this.tokenExpiresAtMillis = refreshed.getTokenExpiresAtMillis();
        tunnelBean.setClientName(refreshed.getClientName());
        tunnelBean.setClientSessionId(refreshed.getClientSessionId());
        tunnelBean.setAccessToken(refreshed.getAccessToken());
        tunnelBean.setTokenTtlSeconds(refreshed.getTokenTtlSeconds());
        tunnelBean.setTokenExpiresAtMillis(refreshed.getTokenExpiresAtMillis());
        tunnelBean.setMaxOnlineInstances(refreshed.getMaxOnlineInstances());
        tunnelBean.setRemoteAddress(host);
        tunnelBean.setRemotePort(port);
        tunnelBean.setTunnelConfigList(nonNullList(refreshed.getTunnelConfigList()));
        tunnelBean.setHttpTunnelConfigList(nonNullList(refreshed.getHttpTunnelConfigList()));
        tunnelBean.setPeerMesh(refreshed.getPeerMesh());
        peerMeshClient.startOrUpdate(refreshed.getPeerMesh());
        if (refreshed.getAuthRefresher() != null) {
            tunnelBean.setAuthRefresher(refreshed.getAuthRefresher());
        }
    }

    private static <T> List<T> nonNullList(List<T> value) {
        return value == null ? List.of() : value;
    }

    public void shutdown() {
        if (!shuttingDown.compareAndSet(false, true)) return;
        cancelProactiveRefresh();
        peerMeshClient.close();
        Channel channel = controlChannel.getAndSet(null);
        if (channel != null) {
            channel.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
        }
        if (localConnection != null) {
            localConnection.close();
            localConnection = null;
        }
        if (localWorkerGroup != null) {
            EventLoopGroup toShutdown = localWorkerGroup;
            localWorkerGroup = null;
            shutdownGroup(toShutdown);
        }
        if (workerGroup != null) {
            EventLoopGroup toShutdown = workerGroup;
            workerGroup = null;
            shutdownGroup(toShutdown);
        }
    }

    private void shutdownGroup(EventLoopGroup group) {
        group.shutdownGracefully(0, 5, TimeUnit.SECONDS)
                .awaitUninterruptibly(10, TimeUnit.SECONDS);
        group.terminationFuture().awaitUninterruptibly(10, TimeUnit.SECONDS);
    }

    public boolean isShuttingDown() {
        return shuttingDown.get();
    }

    public boolean isReconnectSuppressed() {
        return reconnectSuppressed.get();
    }

    public boolean isAuthRefreshInProgress() {
        return authRefreshInProgress.get();
    }

    /**
     * 安排下一次重连。无论 {@code channelInactive} 与连接失败回调的并发情况如何，
     * 同一时刻最多只有一个延时任务在飞。
     */
    public void scheduleReconnect() {
        if (shouldStopConnecting()) return;
        if (authRefreshInProgress.get()) return;
        if (!reconnectScheduled.compareAndSet(false, true)) {
            // 已经有挂起的重连任务，无需再排一次。
            return;
        }
        EventLoopGroup group = workerGroup;
        if (group == null || group.isShuttingDown() || group.isShutdown()) {
            reconnectScheduled.set(false);
            return;
        }
        int attempt = reconnectAttempts.incrementAndGet();
        // Exponential backoff with cap: 2s, 4s, 8s, 16s, 32s, then capped at 60s.
        long delay = Math.min(
                BASE_RECONNECT_DELAY_SECONDS * (1L << Math.min(attempt - 1, 5)),
                MAX_RECONNECT_DELAY_SECONDS);
        log.info("Reconnect attempt {} to {}:{} in {}s", attempt, host, port, delay);
        group.next().schedule(() -> {
            reconnectScheduled.set(false);
            if (shouldStopConnecting()) return;
            try {
                connect();
            } catch (Throwable t) {
                log.error("Reconnect attempt {} threw", attempt, t);
                scheduleReconnect();
            }
        }, delay, TimeUnit.SECONDS);
    }

    private boolean shouldStopConnecting() {
        return shuttingDown.get() || reconnectSuppressed.get();
    }

    private void scheduleProactiveRefresh() {
        if (shouldStopConnecting()) {
            return;
        }
        if (tunnelBean.getAuthRefresher() == null || tokenExpiresAtMillis <= 0) {
            return;
        }
        EventLoopGroup group = workerGroup;
        if (group == null || group.isShuttingDown() || group.isShutdown()) {
            return;
        }
        long delayMillis = proactiveRefreshDelayMillis(System.currentTimeMillis());
        scheduleProactiveRefreshTask(delayMillis);
        log.info("客户端访问令牌将在约 {} 秒后主动刷新", TimeUnit.MILLISECONDS.toSeconds(delayMillis));
    }

    private void scheduleProactiveRefreshRetry() {
        if (shouldStopConnecting()) {
            return;
        }
        EventLoopGroup group = workerGroup;
        if (group == null || group.isShuttingDown() || group.isShutdown()) {
            return;
        }
        long delayMillis = TimeUnit.SECONDS.toMillis(PROACTIVE_REFRESH_RETRY_DELAY_SECONDS);
        scheduleProactiveRefreshTask(delayMillis);
        log.info("客户端访问令牌主动刷新失败, {} 秒后重试", PROACTIVE_REFRESH_RETRY_DELAY_SECONDS);
    }

    private void scheduleProactiveRefreshTask(long delayMillis) {
        EventLoopGroup group = workerGroup;
        if (group == null || group.isShuttingDown() || group.isShutdown()) {
            return;
        }
        EventLoop eventLoop = group.next();
        AtomicReference<ScheduledFuture<?>> holder = new AtomicReference<>();
        ScheduledFuture<?> future = eventLoop.schedule(() -> {
            proactiveRefreshFuture.compareAndSet(holder.get(), null);
            if (shouldStopConnecting()) {
                return;
            }
            if (authRefreshInProgress.get()) {
                scheduleProactiveRefreshRetry();
                return;
            }
            refreshCredentialsWithoutReconnect("客户端访问令牌即将过期");
        }, Math.max(delayMillis, TimeUnit.SECONDS.toMillis(PROACTIVE_REFRESH_MIN_DELAY_SECONDS)), TimeUnit.MILLISECONDS);
        holder.set(future);
        ScheduledFuture<?> previous = proactiveRefreshFuture.getAndSet(future);
        if (previous != null && previous != future) {
            previous.cancel(false);
        }
    }

    private long proactiveRefreshDelayMillis(long nowMillis) {
        long remainingMillis = tokenExpiresAtMillis - nowMillis;
        if (remainingMillis <= 0) {
            return TimeUnit.SECONDS.toMillis(PROACTIVE_REFRESH_MIN_DELAY_SECONDS);
        }
        long leadMillis = proactiveRefreshLeadMillis(remainingMillis);
        long delayMillis = remainingMillis - leadMillis;
        return Math.max(delayMillis, TimeUnit.SECONDS.toMillis(PROACTIVE_REFRESH_MIN_DELAY_SECONDS));
    }

    private long proactiveRefreshLeadMillis(long remainingMillis) {
        long minLeadMillis = TimeUnit.SECONDS.toMillis(PROACTIVE_REFRESH_MIN_LEAD_SECONDS);
        long maxLeadMillis = TimeUnit.SECONDS.toMillis(PROACTIVE_REFRESH_MAX_LEAD_SECONDS);
        if (remainingMillis <= minLeadMillis * 2) {
            return Math.max(TimeUnit.SECONDS.toMillis(PROACTIVE_REFRESH_MIN_DELAY_SECONDS), remainingMillis / 2);
        }
        long tenth = remainingMillis / 10;
        return Math.min(maxLeadMillis, Math.max(minLeadMillis, tenth));
    }

    private void cancelProactiveRefresh() {
        ScheduledFuture<?> future = proactiveRefreshFuture.getAndSet(null);
        if (future != null) {
            future.cancel(false);
        }
    }
}
