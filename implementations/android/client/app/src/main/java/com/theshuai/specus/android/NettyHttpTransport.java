package com.theshuai.specus.android;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Streaming HTTP/1.1 upstream used by Android Direct HTTP routes. */
final class NettyHttpTransport {
    private static final Set<String> SKIPPED_HEADERS = Set.of(
            "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade");
    private static final NioEventLoopGroup EVENT_LOOPS = new NioEventLoopGroup(0, daemonFactory());
    private static final SslContext UPSTREAM_TLS_CONTEXT = buildTlsContext();

    interface SocketProtector {
        void protect(Socket socket) throws IOException;
    }

    interface Listener {
        void onResponseHead(int statusCode, List<String> headers,
                            List<String> trailerNames) throws Exception;

        void onResponseData(byte[] data) throws Exception;

        void onResponseEnd(List<String> trailers) throws Exception;

        default void onFailure(Throwable error) {
        }
    }

    private final URI target;
    private final String method;
    private final List<String> requestHeaders;
    private final String boundedRange;
    private final long contentLength;
    private final List<String> requestTrailerNames;
    private final SocketProtector protector;
    private final Listener listener;
    private final CompletableFuture<Void> ready = new CompletableFuture<>();
    private final CompletableFuture<Void> completed = new CompletableFuture<>();
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final Object lifecycleLock = new Object();
    private volatile Channel channel;

    NettyHttpTransport(URI target, String method, List<String> requestHeaders,
                       String boundedRange, long contentLength, List<String> requestTrailerNames,
                       SocketProtector protector, Listener listener) {
        this.target = target;
        this.method = method;
        this.requestHeaders = requestHeaders == null ? List.of() : List.copyOf(requestHeaders);
        this.boundedRange = boundedRange;
        this.contentLength = contentLength;
        this.requestTrailerNames = validTrailerNames(requestTrailerNames);
        this.protector = protector;
        this.listener = listener;
    }

    void start() {
        if (closed.get()) {
            return;
        }
        String scheme = target == null ? null : target.getScheme();
        String host = target == null ? null : target.getHost();
        if (host == null || scheme == null
                || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            fail(new IOException("invalid HTTP target"));
            return;
        }
        int port = target.getPort() >= 0 ? target.getPort()
                : "https".equalsIgnoreCase(scheme) ? 443 : 80;
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
                        if ("https".equalsIgnoreCase(scheme)) {
                            socketChannel.pipeline().addLast(
                                    tlsHandler(socketChannel, host, port));
                        }
                        socketChannel.pipeline().addLast(new HttpClientCodec());
                        socketChannel.pipeline().addLast(new ResponseHandler());
                    }
                });
        ChannelFuture connect;
        synchronized (lifecycleLock) {
            if (closed.get()) {
                return;
            }
            connect = bootstrap.connect(host, port);
            channel = connect.channel();
        }
        connect.addListener(future -> {
            if (!future.isSuccess()) {
                fail(future.cause() == null
                        ? new IOException("HTTP upstream connect failed") : future.cause());
                return;
            }
            try {
                synchronized (lifecycleLock) {
                    if (closed.get()) {
                        connect.channel().close();
                        return;
                    }
                    HttpRequest request = buildRequest();
                    connect.channel().writeAndFlush(request).addListener(write -> {
                        if (write.isSuccess()) {
                            ready.complete(null);
                        } else {
                            fail(write.cause() == null
                                    ? new IOException("HTTP request head write failed") : write.cause());
                        }
                    });
                }
            } catch (Throwable error) {
                fail(error);
            }
        });
    }

    void writeData(byte[] data) throws Exception {
        awaitReady();
        if (data == null || data.length == 0) {
            return;
        }
        Channel active = requireActive();
        active.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(data))).sync();
    }

    void finishRequest(List<String> trailers) throws Exception {
        awaitReady();
        Channel active = requireActive();
        DefaultLastHttpContent last = new DefaultLastHttpContent(Unpooled.EMPTY_BUFFER);
        appendTrailers(last.trailingHeaders(), trailers, requestTrailerNames);
        active.writeAndFlush(last).sync();
    }

    void awaitCompletion() throws Exception {
        try {
            completed.get();
        } catch (ExecutionException error) {
            Throwable cause = error.getCause() == null ? error : error.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw new IOException("HTTP upstream failed", cause);
        }
    }

    boolean isComplete() {
        return completed.isDone() && !completed.isCompletedExceptionally();
    }

    /**
     * Pauses or resumes reading the upstream response.
     *
     * Response chunks are handed to the SWS2 scheduler without blocking the event loop, so when
     * that queue fills the only remaining backpressure is to stop reading the upstream server.
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
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            active = channel;
        }
        if (active != null) {
            active.close();
        }
        if (!completed.isDone()) {
            completed.completeExceptionally(new IOException("HTTP upstream cancelled"));
        }
        if (!ready.isDone()) {
            ready.completeExceptionally(new IOException("HTTP upstream cancelled"));
        }
    }

    void awaitReady() throws Exception {
        try {
            ready.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException error) {
            Throwable cause = error.getCause() == null ? error : error.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw new IOException("HTTP upstream failed", cause);
        } catch (TimeoutException error) {
            throw new IOException("HTTP upstream connect timed out", error);
        }
    }

    private Channel requireActive() throws IOException {
        Throwable failed = failure.get();
        if (failed != null) {
            throw new IOException(failed.getMessage() == null ? "HTTP upstream failed" : failed.getMessage(), failed);
        }
        Channel active = channel;
        if (active == null || !active.isActive()) {
            throw new IOException("HTTP upstream is closed");
        }
        return active;
    }

    private HttpRequest buildRequest() {
        HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1,
                HttpMethod.valueOf(method), requestTarget(target));
        request.headers().set(HttpHeaderNames.HOST, hostHeader(target));
        boolean hasAcceptEncoding = false;
        for (String header : requestHeaders) {
            int separator = header.indexOf(':');
            if (separator <= 0) continue;
            String name = header.substring(0, separator).trim();
            if (!shouldForward(name)
                    || boundedRange != null && "range".equalsIgnoreCase(name)) {
                continue;
            }
            String rawValue = header.substring(separator + 1);
            if (safeHeaderValue(rawValue)) {
                request.headers().add(name, trimOws(rawValue));
                hasAcceptEncoding |= "accept-encoding".equalsIgnoreCase(name);
            }
        }
        if (boundedRange != null) {
            request.headers().set(HttpHeaderNames.RANGE, boundedRange);
        }
        if (!hasAcceptEncoding) {
            request.headers().set(HttpHeaderNames.ACCEPT_ENCODING, "identity");
        }
        if (!requestTrailerNames.isEmpty()) {
            request.headers().set(HttpHeaderNames.TRAILER, requestTrailerNames);
        }
        if (contentLength >= 0 && requestTrailerNames.isEmpty()) {
            HttpUtil.setContentLength(request, contentLength);
        } else {
            HttpUtil.setTransferEncodingChunked(request, true);
        }
        return request;
    }

    private void protect(SocketChannel socketChannel) throws IOException {
        if (protector != null) {
            protector.protect(((ProtectedNioSocketChannel) socketChannel).socket());
        }
    }

    private final class ResponseHandler extends SimpleChannelInboundHandler<HttpObject> {
        private boolean responseStarted;
        private boolean informational;
        private long responseBytes;
        private List<String> declaredTrailers = List.of();

        @Override
        protected void channelRead0(ChannelHandlerContext context, HttpObject message) {
            try {
                if (message instanceof HttpResponse response) {
                    int status = response.status().code();
                    informational = status >= 100 && status < 200 && status != 101;
                    if (!informational) {
                        if (responseStarted) {
                            throw new IOException("duplicate upstream HTTP response head");
                        }
                        responseStarted = true;
                        declaredTrailers = declaredTrailerNames(response.headers());
                        listener.onResponseHead(status, flattenHeaders(response.headers()), declaredTrailers);
                    }
                }
                if (message instanceof HttpContent content) {
                    if (informational) {
                        if (message instanceof LastHttpContent) informational = false;
                        return;
                    }
                    if (!responseStarted) {
                        throw new IOException("upstream HTTP content arrived before response head");
                    }
                    ByteBuf body = content.content();
                    if (body.isReadable()) {
                        byte[] bytes = new byte[body.readableBytes()];
                        body.getBytes(body.readerIndex(), bytes);
                        responseBytes += bytes.length;
                        if (responseBytes > 64L * 1024 * 1024) {
                            throw new IOException("HTTP response body exceeds limit");
                        }
                        listener.onResponseData(bytes);
                    }
                    if (message instanceof LastHttpContent last) {
                        listener.onResponseEnd(filterTrailers(last.trailingHeaders(), declaredTrailers));
                        completed.complete(null);
                        closed.set(true);
                        context.close();
                        return;
                    }
                }
            } catch (Throwable error) {
                fail(error);
                context.close();
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) throws Exception {
            if (!completed.isDone()) {
                fail(new IOException("upstream HTTP connection closed"));
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
        Throwable cause = error == null ? new IOException("HTTP upstream failed") : error;
        if (!failure.compareAndSet(null, cause)) {
            return;
        }
        try {
            listener.onFailure(cause);
        } catch (Throwable ignored) {
            // Preserve the transport failure as the completion cause.
        }
        ready.completeExceptionally(cause);
        completed.completeExceptionally(cause);
        Channel active = channel;
        if (active != null) {
            active.close();
        }
    }

    static List<String> validTrailerNames(List<String> names) {
        if (names == null || names.isEmpty()) return List.of();
        Set<String> seen = new HashSet<>();
        List<String> result = new ArrayList<>();
        for (String name : names) {
            String trimmed = name == null ? "" : name.trim();
            if (isHeaderName(trimmed) && shouldForward(trimmed)
                    && seen.add(trimmed.toLowerCase(Locale.ROOT))) {
                result.add(trimmed);
            }
        }
        return List.copyOf(result);
    }

    static void appendTrailers(HttpHeaders target, List<String> trailers,
                               List<String> declaredNames) {
        if (trailers == null || trailers.isEmpty()) return;
        Set<String> declared = new HashSet<>();
        declaredNames.forEach(name -> declared.add(name.toLowerCase(Locale.ROOT)));
        for (String trailer : trailers) {
            int separator = trailer == null ? -1 : trailer.indexOf(':');
            if (separator <= 0) continue;
            String name = trailer.substring(0, separator).trim();
            String rawValue = trailer.substring(separator + 1);
            String value = trimOws(rawValue);
            if (declared.contains(name.toLowerCase(Locale.ROOT))
                    && isHeaderName(name) && shouldForward(name) && safeHeaderValue(rawValue)) {
                target.add(name, value);
            }
        }
    }

    private static List<String> declaredTrailerNames(HttpHeaders headers) {
        List<String> names = new ArrayList<>();
        for (String value : headers.getAll(HttpHeaderNames.TRAILER)) {
            for (String name : value.split(",")) names.add(name);
        }
        return validTrailerNames(names);
    }

    private static List<String> filterTrailers(HttpHeaders headers, List<String> declaredNames) {
        Set<String> declared = new HashSet<>();
        declaredNames.forEach(name -> declared.add(name.toLowerCase(Locale.ROOT)));
        List<String> result = new ArrayList<>();
        headers.forEach(header -> {
            String name = header.getKey();
            String value = header.getValue();
            if (declared.contains(name.toLowerCase(Locale.ROOT))
                    && isHeaderName(name) && shouldForward(name) && safeHeaderValue(value)) {
                result.add(name + ":" + value);
            }
        });
        return result;
    }

    private static List<String> flattenHeaders(HttpHeaders headers) {
        List<String> result = new ArrayList<>();
        headers.forEach(header -> {
            if (shouldForward(header.getKey())) {
                result.add(header.getKey() + ":" + header.getValue());
            }
        });
        return result;
    }

    private static boolean shouldForward(String name) {
        return name != null && !SKIPPED_HEADERS.contains(name.toLowerCase(Locale.ROOT));
    }

    private static boolean isHeaderName(String name) {
        if (name == null || name.isBlank()) return false;
        for (int index = 0; index < name.length(); index++) {
            char ch = name.charAt(index);
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                    || (ch >= '0' && ch <= '9') || "!#$%&'*+-.^_`|~".indexOf(ch) >= 0)) {
                return false;
            }
        }
        return true;
    }

    private static boolean safeHeaderValue(String value) {
        if (value == null || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) return false;
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            if (ch != '\t' && (ch < ' ' || ch == 0x7f)) return false;
        }
        return true;
    }

    private static String trimOws(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && (value.charAt(start) == ' ' || value.charAt(start) == '\t')) start++;
        while (end > start && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t')) end--;
        return value.substring(start, end);
    }

    private static String requestTarget(URI target) {
        String path = target.getRawPath();
        if (path == null || path.isEmpty()) path = "/";
        return target.getRawQuery() == null ? path : path + "?" + target.getRawQuery();
    }

    private static String hostHeader(URI target) {
        String host = target.getHost().contains(":") ? "[" + target.getHost() + "]" : target.getHost();
        int port = target.getPort();
        boolean defaultPort = port < 0 || port == 80 && "http".equalsIgnoreCase(target.getScheme())
                || port == 443 && "https".equalsIgnoreCase(target.getScheme());
        return defaultPort ? host : host + ":" + port;
    }

    /**
     * Builds the TLS handler for one upstream connection, with hostname verification enabled. The
     * trust manager proves a certificate is trusted, not that it belongs to the host being
     * dialled; without this a valid certificate for any host would be accepted for every host.
     */
    private static io.netty.handler.ssl.SslHandler tlsHandler(
            io.netty.channel.socket.SocketChannel channel, String host, int port) {
        io.netty.handler.ssl.SslHandler handler =
                UPSTREAM_TLS_CONTEXT.newHandler(channel.alloc(), host, port);
        UpstreamTlsPolicy.current().applyHostnameVerification(handler.engine());
        return handler;
    }

    private static SslContext buildTlsContext() {
        // Verified by default; see UpstreamTlsPolicy for why, and for how a self-signed target is
        // described. This used to trust every certificate unconditionally.
        return UpstreamTlsPolicy.current().buildContext();
    }

    private static ThreadFactory daemonFactory() {
        return task -> {
            Thread thread = new Thread(task, "specus-android-netty-http");
            thread.setDaemon(true);
            return thread;
        };
    }

    private static final class ProtectedNioSocketChannel extends NioSocketChannel {
        private ProtectedNioSocketChannel() {
            super();
        }

        Socket socket() {
            return javaChannel().socket();
        }
    }
}
