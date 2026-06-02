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
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLException;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

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
    private final SecureRandom secureRandom = new SecureRandom();
    private volatile EventLoopGroup workerGroup;
    private final SslContext sslContext;

    // Cap backoff so a long outage doesn't park the client forever.
    private static final int MAX_RECONNECT_DELAY_SECONDS = 60;
    private static final int MAX_RECONNECT_ATTEMPTS = 30;
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

    public void start() throws InterruptedException {
        if (workerGroup == null) {
            workerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        }
        bootstrap.group(workerGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                .option(ChannelOption.SO_KEEPALIVE, true)
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
                        ch.pipeline().addLast(new LoginResponseHandler());
                        ch.pipeline().addLast(new MessageResponseHandler());
                        ch.pipeline().addLast(new DirectHttpRequestHandler(tunnelBean.getHttpTunnelConfigList()));
                        ch.pipeline().addLast(new CustomHttpRequestHandler());
                        ch.pipeline().addLast(new LogoutResponseHandler());
                        ch.pipeline().addLast(new PacketEncoder());
                        ch.pipeline().addLast(new HeartBeatTimerHandler(NettyClient.this));
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

    public void connect() throws InterruptedException {
        bootstrap.connect(host, port).addListener((ChannelFutureListener) listener -> {
            if (listener.isSuccess()) {
                reconnectAttempts.set(0);
                Channel channel = listener.channel();
                LoginRequestPacket loginRequestPacket = new LoginRequestPacket();
                loginRequestPacket.setClientName(clientName);
                String timestamp = String.valueOf(System.currentTimeMillis());
                String nonce = generateNonce();
                loginRequestPacket.setTimestamp(timestamp);
                loginRequestPacket.setNonce(nonce);
                String message = clientName + "\n" + timestamp + "\n" + nonce;
                loginRequestPacket.setCheckSign(HmacSigner.hmacSha256(passwordHash, message));
                channel.writeAndFlush(loginRequestPacket);
                log.info("Connected to {}:{}", host, port);
            } else {
                scheduleReconnect(listener.channel().eventLoop());
            }
        });
    }

    private String generateNonce() {
        byte[] nonceBytes = new byte[NONCE_BYTES];
        secureRandom.nextBytes(nonceBytes);
        return HexFormat.of().formatHex(nonceBytes);
    }

    public void shutdown() {
        if (workerGroup != null) {
            EventLoopGroup toShutdown = workerGroup;
            workerGroup = null;
            toShutdown.shutdownGracefully();
        }
    }

    private void scheduleReconnect(EventLoop loop) {
        int attempt = reconnectAttempts.incrementAndGet();
        if (attempt > MAX_RECONNECT_ATTEMPTS) {
            log.error("Giving up reconnect after {} attempts to {}:{}", attempt - 1, host, port);
            return;
        }
        // Exponential backoff with cap: 2s, 4s, 8s, 16s, 32s, then capped at 60s.
        long delay = Math.min(
                BASE_RECONNECT_DELAY_SECONDS * (1L << Math.min(attempt - 1, 5)),
                MAX_RECONNECT_DELAY_SECONDS);
        log.info("Reconnect attempt {} to {}:{} in {}s", attempt, host, port, delay);
        loop.schedule(() -> {
            try {
                connect();
            } catch (Exception e) {
                log.error("Reconnect attempt {} failed", attempt, e);
            }
        }, delay, TimeUnit.SECONDS);
    }
}
