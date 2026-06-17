package com.theshuai.tunnelclient.client;

import com.theshuai.common.codec.PacketDecoder;
import com.theshuai.common.codec.PacketEncoder;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.handler.CustomHttpRequestHandler;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.security.HmacSigner;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.handler.*;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.*;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;

import java.io.File;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLException;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

/**
 * 控制连接的 Netty 客户端：负责建立 TCP 连接、签名登录、断线后指数退避重连。
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
    private final String clientName;
    private final byte[] passwordHash;
    private final String host;
    private final int port;
    private final TunnelBean tunnelBean;
    private final Bootstrap bootstrap = new Bootstrap();
    private final AtomicInteger reconnectAttempts = new AtomicInteger(0);
    private final AtomicBoolean reconnectScheduled = new AtomicBoolean(false);
    private final AtomicBoolean shuttingDown = new AtomicBoolean(false);
    private final SecureRandom secureRandom = new SecureRandom();
    private volatile EventLoopGroup workerGroup;
    private volatile EventLoopGroup localWorkerGroup;
    private volatile TcpConnection localConnection;
    private final SslContext sslContext;

    /** 退避上限：连续 5 次失败后稳定到一分钟一次，长期网络故障可自愈。 */
    private static final int MAX_RECONNECT_DELAY_SECONDS = 60;
    private static final long BASE_RECONNECT_DELAY_SECONDS = 2L;
    private static final int NONCE_BYTES = 16;

    public NettyClient(TunnelBean tunnelBean) {
        this(tunnelBean, null);
    }

    public NettyClient(TunnelBean tunnelBean, SslContext sslContext) {
        this.tunnelBean = tunnelBean;
        this.clientName = tunnelBean.getClientName();
        // Hash the password once at construction so we never keep the plaintext
        // around and never send it over the wire.
        this.passwordHash = HmacSigner.sha256(tunnelBean.getPassword());
        this.host = tunnelBean.getRemoteAddress();
        this.port = tunnelBean.getRemotePort();
        this.sslContext = sslContext;
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
                        ch.pipeline().addLast(new MessageResponseHandler(sharedLocalConnection));
                        ch.pipeline().addLast(new DirectHttpRequestHandler(tunnelBean.getHttpTunnelConfigList()));
                        ch.pipeline().addLast(new CustomHttpRequestHandler());
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
        if (shuttingDown.get()) return;
        bootstrap.connect(host, port).addListener((ChannelFutureListener) future -> {
            if (shuttingDown.get()) {
                if (future.isSuccess()) future.channel().close();
                return;
            }
            if (future.isSuccess()) {
                Channel channel = future.channel();
                log.info("Connected to {}:{} (awaiting login response)", host, port);
                sendLoginRequest(channel);
            } else {
                log.warn("Connect to {}:{} failed: {}", host, port,
                        future.cause() == null ? "unknown" : future.cause().getMessage());
                scheduleReconnect();
            }
        });
    }

    private void sendLoginRequest(Channel channel) {
        LoginRequestPacket loginRequestPacket = new LoginRequestPacket();
        loginRequestPacket.setClientName(clientName);
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = generateNonce();
        loginRequestPacket.setTimestamp(timestamp);
        loginRequestPacket.setNonce(nonce);
        String message = clientName + "\n" + timestamp + "\n" + nonce;
        loginRequestPacket.setCheckSign(HmacSigner.hmacSha256(passwordHash, message));
        channel.writeAndFlush(loginRequestPacket);
    }

    /** 由 {@link LoginResponseHandler} 在收到 success=true 时回调，重置退避计数。 */
    public void onLoginSuccess() {
        int prior = reconnectAttempts.getAndSet(0);
        if (prior > 0) {
            log.info("Login succeeded, reconnect backoff reset (was attempt #{})", prior);
        }
    }

    private String generateNonce() {
        byte[] nonceBytes = new byte[NONCE_BYTES];
        secureRandom.nextBytes(nonceBytes);
        return HexFormat.of().formatHex(nonceBytes);
    }

    public void shutdown() {
        if (!shuttingDown.compareAndSet(false, true)) return;
        if (localConnection != null) {
            localConnection.close();
            localConnection = null;
        }
        if (localWorkerGroup != null) {
            EventLoopGroup toShutdown = localWorkerGroup;
            localWorkerGroup = null;
            toShutdown.shutdownGracefully();
        }
        if (workerGroup != null) {
            EventLoopGroup toShutdown = workerGroup;
            workerGroup = null;
            toShutdown.shutdownGracefully();
        }
    }

    /**
     * 安排下一次重连。无论 {@code channelInactive} 与连接失败回调的并发情况如何，
     * 同一时刻最多只有一个延时任务在飞。
     */
    public void scheduleReconnect() {
        if (shuttingDown.get()) return;
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
            if (shuttingDown.get()) return;
            try {
                connect();
            } catch (Throwable t) {
                log.error("Reconnect attempt {} threw", attempt, t);
                scheduleReconnect();
            }
        }, delay, TimeUnit.SECONDS);
    }
}
