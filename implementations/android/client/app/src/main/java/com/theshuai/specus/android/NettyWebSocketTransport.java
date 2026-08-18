package com.theshuai.specus.android;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.ContinuationWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolConfig;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketVersion;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.util.ReferenceCountUtil;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A frame-preserving WebSocket client for the Android route data plane.
 *
 * <p>OkHttp intentionally exposes complete messages and hides native ping/pong frames. SWS2 is a
 * frame protocol, so using the message API changes continuation, FIN, RSV and control-frame
 * semantics. Netty exposes the same frame model used by the Java reference client while still
 * allowing the underlying socket to be protected from the Android VPN.</p>
 */
final class NettyWebSocketTransport {
    /** Java-reference physical data-frame limit before SWS2 continuation normalization. */
    static final int MAX_FRAME_BYTES = SpecusCore.WebSocketSupport.MAX_MESSAGE_BYTES;
    static final long MAX_PENDING_WRITE_BYTES = 4L * 1024L * 1024L;
    private static final Set<String> SKIPPED_HEADERS = Set.of(
            "connection", "content-length", "host", "keep-alive",
            "proxy-authenticate", "proxy-authorization", "te", "trailer",
            "transfer-encoding", "upgrade", "sec-websocket-key",
            "sec-websocket-version", "sec-websocket-extensions",
            "sec-websocket-protocol", "sec-websocket-accept");
    private static final NioEventLoopGroup EVENT_LOOPS = new NioEventLoopGroup(0, daemonFactory());
    private static final SslContext INSECURE_CLIENT_TLS = buildTlsContext();

    interface SocketProtector {
        void protect(Socket socket) throws IOException;
    }

    interface Listener {
        void onOpen();

        void onFrame(int opcode, boolean fin, int rsv, int closeCode, byte[] payload);

        void onClosed(String detail);

        void onFailure(Throwable error);
    }

    private final URI target;
    private final Object handshakeHeaders;
    private final SocketProtector protector;
    private final Listener listener;
    private final AtomicBoolean finished = new AtomicBoolean(false);
    private final PendingWriteLimiter pendingWrites =
            new PendingWriteLimiter(MAX_PENDING_WRITE_BYTES);
    private final Object lifecycleLock = new Object();
    private volatile Channel channel;
    private volatile boolean opened;

    NettyWebSocketTransport(URI target, Object handshakeHeaders,
                            SocketProtector protector, Listener listener) {
        this.target = target;
        this.handshakeHeaders = handshakeHeaders;
        this.protector = protector;
        this.listener = listener;
    }

    void start() {
        if (finished.get()) {
            return;
        }
        String host = target == null ? null : target.getHost();
        String scheme = target == null ? null : target.getScheme();
        if (host == null || scheme == null
                || !("ws".equalsIgnoreCase(scheme) || "wss".equalsIgnoreCase(scheme))) {
            fail(new IOException("invalid WebSocket target"));
            return;
        }
        int port = target.getPort() >= 0 ? target.getPort()
                : "wss".equalsIgnoreCase(scheme) ? 443 : 80;
        HttpHeaders headers;
        try {
            headers = buildHeaders(handshakeHeaders);
        } catch (RuntimeException error) {
            fail(error);
            return;
        }

        WebSocketClientProtocolConfig protocol = WebSocketClientProtocolConfig.newBuilder()
                .webSocketUri(target)
                .version(WebSocketVersion.V13)
                .allowExtensions(true)
                .customHeaders(headers)
                .maxFramePayloadLength(MAX_FRAME_BYTES)
                .performMasking(true)
                .allowMaskMismatch(false)
                .handleCloseFrames(false)
                .dropPongFrames(false)
                .handshakeTimeoutMillis(5_000L)
                .forceCloseTimeoutMillis(5_000L)
                .build();

        Bootstrap bootstrap = new Bootstrap()
                .group(EVENT_LOOPS)
                .channelFactory(ProtectedNioSocketChannel::new)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5_000)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.TCP_NODELAY, true)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel socketChannel) throws Exception {
                        protect(socketChannel);
                        if ("wss".equalsIgnoreCase(scheme)) {
                            socketChannel.pipeline().addLast(
                                    INSECURE_CLIENT_TLS.newHandler(socketChannel.alloc(), host, port));
                        }
                        socketChannel.pipeline().addLast(new HttpClientCodec());
                        socketChannel.pipeline().addLast(new HttpObjectAggregator(65_536));
                        // WebSocketProtocolHandler normally terminates ping locally. Consume it
                        // first so the peer across SWS2 remains the endpoint that answers it.
                        socketChannel.pipeline().addLast(new PingFrameTap());
                        socketChannel.pipeline().addLast(new WebSocketClientProtocolHandler(protocol));
                        socketChannel.pipeline().addLast(new FrameHandler());
                    }
                });
        ChannelFuture connect;
        synchronized (lifecycleLock) {
            if (finished.get()) {
                return;
            }
            connect = bootstrap.connect(host, port);
            channel = connect.channel();
        }
        connect.addListener(future -> {
            if (!future.isSuccess()) {
                fail(future.cause() == null
                        ? new IOException("WebSocket connect failed") : future.cause());
            }
        });
    }

    CompletableFuture<Void> send(int opcode, boolean fin, int rsv,
                                 int closeCode, byte[] payload) {
        Channel active = channel;
        if (!opened || finished.get() || active == null || !active.isActive()) {
            return failedFuture(new IOException("local websocket frame write rejected"));
        }
        byte[] content = payload == null ? new byte[0] : payload;
        long reservedBytes = Math.max(1, content.length);
        if (!pendingWrites.reserve(reservedBytes)) {
            return failedFuture(new IOException("local websocket pending writes exceed limit"));
        }
        final WebSocketFrame frame;
        try {
            frame = toNettyFrame(opcode, fin, rsv, closeCode,
                    content);
        } catch (RuntimeException error) {
            pendingWrites.release(reservedBytes);
            return failedFuture(error);
        }
        CompletableFuture<Void> completion = new CompletableFuture<>();
        try {
            active.writeAndFlush(frame).addListener(future -> {
                pendingWrites.release(reservedBytes);
                if (future.isSuccess()) {
                    completion.complete(null);
                    return;
                }
                Throwable error = future.cause() == null
                        ? new IOException("WebSocket frame write failed") : future.cause();
                completion.completeExceptionally(error);
                // The SWS2 owner observes this future and emits the stream RST. Suppress the
                // generic transport callback so a racing channelInactive cannot emit FIN first.
                opened = false;
                finished.set(true);
                active.close();
            });
        } catch (RuntimeException error) {
            ReferenceCountUtil.release(frame);
            pendingWrites.release(reservedBytes);
            completion.completeExceptionally(error);
        }
        return completion;
    }

    /**
     * Pauses or resumes reading from the local WebSocket.
     *
     * Frames are forwarded to the control channel without blocking the event loop, so the only way
     * to stop a fast local server from outrunning a saturated SWS2 send queue is to stop reading it.
     */
    void setReceiving(boolean receiving) {
        Channel active = channel;
        if (active == null) {
            return;
        }
        try {
            active.config().setAutoRead(receiving);
            if (receiving) {
                active.read();
            }
        } catch (RuntimeException ignored) {
            // A channel closing underneath us needs no flow control.
        }
    }

    void close() {
        Channel active;
        synchronized (lifecycleLock) {
            if (!finished.compareAndSet(false, true)) {
                return;
            }
            active = channel;
        }
        if (active != null) {
            active.close();
        }
    }

    private void protect(SocketChannel socketChannel) throws IOException {
        if (protector == null) {
            return;
        }
        Socket socket = ((ProtectedNioSocketChannel) socketChannel).socket();
        protector.protect(socket);
    }

    private static final class ProtectedNioSocketChannel extends NioSocketChannel {
        private ProtectedNioSocketChannel() {
            super();
        }

        Socket socket() {
            return javaChannel().socket();
        }
    }

    private final class PingFrameTap extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext context, Object message) throws Exception {
            if (message instanceof PingWebSocketFrame ping) {
                try {
                    ByteBuf content = ping.content();
                    byte[] payload = new byte[content.readableBytes()];
                    content.getBytes(content.readerIndex(), payload);
                    listener.onFrame(0x9, true, 0, 0, payload);
                } finally {
                    ReferenceCountUtil.release(message);
                }
                return;
            }
            super.channelRead(context, message);
        }
    }

    private final class FrameHandler extends SimpleChannelInboundHandler<WebSocketFrame> {
        @Override
        public void userEventTriggered(ChannelHandlerContext context, Object event) throws Exception {
            if (event == WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE) {
                if (!finished.get()) {
                    opened = true;
                    listener.onOpen();
                }
                return;
            }
            super.userEventTriggered(context, event);
        }

        @Override
        protected void channelRead0(ChannelHandlerContext context, WebSocketFrame frame) {
            int opcode = opcode(frame);
            int closeCode = 0;
            byte[] payload;
            ByteBuf content = frame.content();
            int offset = content.readerIndex();
            int length = content.readableBytes();
            if (frame instanceof CloseWebSocketFrame close) {
                int status = close.statusCode();
                closeCode = status < 0 ? 0 : status;
                if (closeCode != 0 && length >= 2) {
                    offset += 2;
                    length -= 2;
                }
            }
            payload = new byte[length];
            content.getBytes(offset, payload);
            listener.onFrame(opcode, frame.isFinalFragment(), frame.rsv(), closeCode, payload);
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) throws Exception {
            opened = false;
            if (finished.compareAndSet(false, true)) {
                listener.onClosed("local websocket closed");
            }
            super.channelInactive(context);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext context, Throwable error) {
            fail(error);
            context.close();
        }
    }

    private void fail(Throwable error) {
        opened = false;
        if (!finished.compareAndSet(false, true)) {
            return;
        }
        try {
            listener.onFailure(error == null ? new IOException("WebSocket transport failed") : error);
        } finally {
            Channel active = channel;
            if (active != null) {
                active.close();
            }
        }
    }

    private static CompletableFuture<Void> failedFuture(Throwable error) {
        CompletableFuture<Void> completion = new CompletableFuture<>();
        completion.completeExceptionally(error);
        return completion;
    }

    static final class PendingWriteLimiter {
        private final long maximumBytes;
        private final AtomicLong pendingBytes = new AtomicLong();

        PendingWriteLimiter(long maximumBytes) {
            if (maximumBytes <= 0L) {
                throw new IllegalArgumentException("pending write limit must be positive");
            }
            this.maximumBytes = maximumBytes;
        }

        boolean reserve(long bytes) {
            if (bytes <= 0L || bytes > maximumBytes) {
                return false;
            }
            while (true) {
                long current = pendingBytes.get();
                if (current > maximumBytes - bytes) {
                    return false;
                }
                if (pendingBytes.compareAndSet(current, current + bytes)) {
                    return true;
                }
            }
        }

        void release(long bytes) {
            if (bytes <= 0L) {
                return;
            }
            long remaining = pendingBytes.addAndGet(-bytes);
            if (remaining < 0L) {
                pendingBytes.addAndGet(bytes);
                throw new IllegalStateException("pending websocket writes released twice");
            }
        }

        long pendingBytes() {
            return pendingBytes.get();
        }
    }

    static WebSocketFrame toNettyFrame(int opcode, boolean fin, int rsv,
                                       int closeCode, byte[] payload) {
        ByteBuf content = Unpooled.wrappedBuffer(payload);
        return switch (opcode) {
            case 0x0 -> new ContinuationWebSocketFrame(fin, rsv, content);
            case 0x1 -> new TextWebSocketFrame(fin, rsv, content);
            case 0x2 -> new BinaryWebSocketFrame(fin, rsv, content);
            case 0x8 -> {
                if (closeCode == 0) {
                    yield new CloseWebSocketFrame(fin, rsv, content);
                }
                ByteBuf close = Unpooled.buffer(2 + payload.length);
                close.writeShort(closeCode);
                close.writeBytes(payload);
                content.release();
                yield new CloseWebSocketFrame(fin, rsv, close);
            }
            case 0x9 -> new PingWebSocketFrame(content);
            case 0xA -> new PongWebSocketFrame(content);
            default -> {
                content.release();
                throw new IllegalArgumentException("unsupported WebSocket opcode");
            }
        };
    }

    static int opcode(WebSocketFrame frame) {
        if (frame instanceof ContinuationWebSocketFrame) return 0x0;
        if (frame instanceof TextWebSocketFrame) return 0x1;
        if (frame instanceof BinaryWebSocketFrame) return 0x2;
        if (frame instanceof CloseWebSocketFrame) return 0x8;
        if (frame instanceof PingWebSocketFrame) return 0x9;
        if (frame instanceof PongWebSocketFrame) return 0xA;
        throw new IllegalArgumentException("unsupported WebSocket frame");
    }

    private static HttpHeaders buildHeaders(Object rawHeaders) {
        HttpHeaders headers = new DefaultHttpHeaders();
        if (!(rawHeaders instanceof List<?> values)) {
            return headers;
        }
        for (Object value : values) {
            String line = value == null ? "" : value.toString();
            int separator = line.indexOf(':');
            if (separator <= 0) {
                continue;
            }
            String name = line.substring(0, separator).trim();
            String normalized = name.toLowerCase(Locale.ROOT);
            String rawValue = line.substring(separator + 1);
            if (name.isEmpty() || SKIPPED_HEADERS.contains(normalized)
                    || rawValue.indexOf('\r') >= 0 || rawValue.indexOf('\n') >= 0) {
                continue;
            }
            headers.add(name, trimOws(rawValue));
        }
        return headers;
    }

    private static String trimOws(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && (value.charAt(start) == ' ' || value.charAt(start) == '\t')) start++;
        while (end > start && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t')) end--;
        return value.substring(start, end);
    }

    private static SslContext buildTlsContext() {
        try {
            return SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();
        } catch (Exception error) {
            throw new ExceptionInInitializerError(error);
        }
    }

    private static ThreadFactory daemonFactory() {
        return task -> {
            Thread thread = new Thread(task, "specus-android-netty-ws");
            thread.setDaemon(true);
            return thread;
        };
    }
}
