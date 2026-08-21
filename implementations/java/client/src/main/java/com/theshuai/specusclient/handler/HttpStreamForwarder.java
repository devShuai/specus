package com.theshuai.specusclient.handler;

import com.theshuai.common.service.ExecuteService;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
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
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import com.theshuai.specusclient.client.UpstreamTlsPolicyHolder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Streams one HTTP request and response over mandatory NAT stream v2 frames. */
final class HttpStreamForwarder implements Runnable {
    private static final int MAX_REQUEST_BYTES = 16 * 1024 * 1024;
    private static final long MAX_RESPONSE_BYTES = 64L * 1024L * 1024L;
    private static final long WRITE_TIMEOUT_SECONDS = 30;
    private static final Set<String> SKIPPED_HEADERS = Set.of(
            "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade");
    private static final SslContext LOCAL_HTTP_SSL_CONTEXT = buildLocalHttpSslContext();

    private final NatClientHandler owner;
    private final int streamId;
    private final Map<String, Object> metadata;
    private final Map<String, String> routes;
    private final EventLoopGroup workerGroup;
    private final StreamingBodyInput requestBody;
    private final AtomicBoolean remoteReset = new AtomicBoolean();
    private volatile Channel upstreamChannel;

    HttpStreamForwarder(NatClientHandler owner, int streamId, Map<String, Object> metadata,
                        Map<String, String> routes, EventLoopGroup workerGroup) {
        this.owner = owner;
        this.streamId = streamId;
        this.metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
        this.routes = routes;
        this.workerGroup = workerGroup;
        this.requestBody = new StreamingBodyInput(bytes -> owner.sendHttpWindowUpdate(streamId, bytes));
    }

    void start() {
        ExecuteService.submit(this);
    }

    boolean onData(byte[] data) {
        return requestBody.offer(data);
    }

    boolean onRequestFin(Map<String, Object> trailers) {
        return requestBody.finish(stringList(trailers == null ? null : trailers.get("trailers")));
    }

    void cancel(String reason) {
        remoteReset.set(true);
        requestBody.abort(reason);
        Channel channel = upstreamChannel;
        if (channel != null) {
            channel.close();
        }
    }

    @Override
    public void run() {
        UpstreamExchange exchange = null;
        try {
            String method = requiredText("method");
            String route = requiredText("route");
            String relativePath = text(metadata.get("relativePath"));
            String rawQuery = text(metadata.get("rawQuery"));
            URI target = HttpRouteTargetResolver.buildTarget(routes.get(route), relativePath, rawQuery);
            long contentLength = number(metadata.get("contentLength"), -1L);
            if (contentLength > MAX_REQUEST_BYTES) {
                throw new IOException("HTTP 请求体超过限制");
            }
            List<String> headers = stringList(metadata.get("headers"));
            List<String> trailerNames = validTrailerNames(stringList(metadata.get("trailerNames")));
            String range = HttpRouteTargetResolver.boundedRange(firstHeader(headers, "range"));
            exchange = connect(target);
            upstreamChannel = exchange.channel();
            UpstreamExchange requestExchange = exchange;
            ExecuteService.submit(() -> pumpRequest(requestExchange, target, method, contentLength,
                    headers, range, trailerNames));

            UpstreamEvent event = exchange.take();
            if (!(event instanceof ResponseHead head)) {
                throw eventError(event, "upstream closed before HTTP response head");
            }
            owner.sendHttpResponseHead(streamId, head.statusCode(), head.headers(), head.trailerNames())
                    .get(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            long total = 0;
            while (true) {
                event = exchange.take();
                if (event instanceof ResponseData data) {
                    total += data.bytes().length;
                    if (total > MAX_RESPONSE_BYTES) {
                        throw new IOException("HTTP 响应体超过限制");
                    }
                    owner.sendHttpResponseData(streamId, data.bytes())
                            .get(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                } else if (event instanceof ResponseEnd end) {
                    owner.finishHttpResponse(streamId, end.trailers())
                            .get(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    break;
                } else {
                    throw eventError(event, "upstream HTTP response ended unexpectedly");
                }
            }
        } catch (Exception error) {
            if (!remoteReset.get()) {
                Throwable cause = error;
                while (cause.getCause() != null
                        && (cause instanceof java.util.concurrent.ExecutionException
                        || cause instanceof java.util.concurrent.CompletionException)) {
                    cause = cause.getCause();
                }
                owner.failHttpStream(streamId,
                        cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage());
            }
        } finally {
            if (exchange != null) {
                exchange.close();
            }
            upstreamChannel = null;
            owner.httpForwarderDone(streamId, this);
            requestBody.closeQuietly();
        }
    }

    private String requiredText(String key) {
        String value = text(metadata.get(key));
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("HTTP OPEN missing " + key);
        }
        return value;
    }

    private UpstreamExchange connect(URI target) throws Exception {
        UpstreamExchange exchange = new UpstreamExchange();
        int port = target.getPort() >= 0 ? target.getPort()
                : "https".equalsIgnoreCase(target.getScheme()) ? 443 : 80;
        Bootstrap bootstrap = new Bootstrap()
                .group(workerGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.AUTO_READ, false)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) {
                        if ("https".equalsIgnoreCase(target.getScheme())) {
                            io.netty.handler.ssl.SslHandler sslHandler = LOCAL_HTTP_SSL_CONTEXT
                                    .newHandler(channel.alloc(), target.getHost(), port);
                            // A trust manager proves the certificate is trusted, not that it
                            // belongs to this host. Without this a valid certificate for any host
                            // would be accepted for every host.
                            UpstreamTlsPolicyHolder.current()
                                    .applyHostnameVerification(sslHandler.engine());
                            channel.pipeline().addLast(sslHandler);
                        }
                        channel.pipeline().addLast(new HttpClientCodec());
                        channel.pipeline().addLast(new UpstreamResponseHandler(exchange));
                    }
                });
        Channel channel = bootstrap.connect(target.getHost(), port).sync().channel();
        exchange.bind(channel);
        channel.read();
        return exchange;
    }

    private void pumpRequest(UpstreamExchange exchange, URI target, String method,
                             long contentLength, List<String> headers, String range,
                             List<String> trailerNames) {
        Channel channel = exchange.channel();
        try {
            byte[] buffer = new byte[64 * 1024];
            HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1,
                    HttpMethod.valueOf(method), requestTarget(target));
            request.headers().set(HttpHeaderNames.HOST, hostHeader(target));
            for (String header : headers) {
                int separator = header.indexOf(':');
                if (separator <= 0) continue;
                String name = header.substring(0, separator).trim();
                if (!shouldForward(name) || (range != null && "range".equalsIgnoreCase(name))) continue;
                String value = header.substring(separator + 1);
                if (safeHeaderValue(value)) request.headers().add(name, value);
            }
            bindUpstreamAuthority(request.headers(), target);
            if (range != null) request.headers().set(HttpHeaderNames.RANGE, range);
            if (!trailerNames.isEmpty()) {
                request.headers().set(HttpHeaderNames.TRAILER, trailerNames);
            }
            // Request trailers arrive only with FIN, after streaming has begun. Chunked
            // transfer keeps that final metadata representable without buffering the body.
            boolean hasTrailers = !trailerNames.isEmpty();
            if (contentLength >= 0 && !hasTrailers) {
                HttpUtil.setContentLength(request, contentLength);
            } else {
                HttpUtil.setTransferEncodingChunked(request, true);
            }
            channel.writeAndFlush(request).sync();

            long forwarded = 0;
            for (int read; (read = requestBody.read(buffer)) >= 0; ) {
                if (read == 0) continue;
                forwarded += read;
                if (contentLength >= 0 && forwarded > contentLength) {
                    throw new IOException("HTTP request DATA exceeds declared contentLength");
                }
                channel.writeAndFlush(new DefaultHttpContent(
                        Unpooled.wrappedBuffer(Arrays.copyOf(buffer, read)))).sync();
            }
            if (contentLength >= 0 && forwarded != contentLength) {
                throw new IOException("HTTP request body does not match declared contentLength");
            }
            DefaultLastHttpContent last = new DefaultLastHttpContent(Unpooled.EMPTY_BUFFER);
            appendTrailers(last.trailingHeaders(), requestBody.trailers(), trailerNames);
            channel.writeAndFlush(last).sync();
        } catch (Exception error) {
            exchange.fail(error);
            channel.close();
        }
    }

    private static SslContext buildLocalHttpSslContext() {
        // Verified by default; see UpstreamTlsConfig for why, and for how a self-signed target is
        // described. This used to trust every certificate unconditionally.
        return UpstreamTlsPolicyHolder.current().buildContext();
    }

    static void bindUpstreamAuthority(HttpHeaders headers, URI target) {
        String origin = httpOriginOf(target);
        if (origin == null) {
            return;
        }
        if (headers.contains("Origin")) {
            headers.set("Origin", origin);
        }
        if (headers.contains("Referer")) {
            headers.set("Referer", rewriteRefererOrigin(headers.get("Referer"), origin));
        }
        if ("cross-site".equalsIgnoreCase(headers.get("Sec-Fetch-Site"))) {
            headers.set("Sec-Fetch-Site", "same-origin");
        }
    }

    static String httpOriginOf(URI target) {
        if (target == null || target.getHost() == null || target.getHost().isBlank()) {
            return null;
        }
        String scheme = target.getScheme() == null ? "" : target.getScheme().toLowerCase(Locale.ROOT);
        if ("ws".equals(scheme)) {
            scheme = "http";
        } else if ("wss".equals(scheme)) {
            scheme = "https";
        } else if (!"http".equals(scheme) && !"https".equals(scheme)) {
            return null;
        }
        int port = target.getPort();
        return port > 0 ? scheme + "://" + target.getHost() + ":" + port : scheme + "://" + target.getHost();
    }

    private static String rewriteRefererOrigin(String referer, String origin) {
        try {
            URI parsed = URI.create(referer == null ? "" : referer.trim());
            URI base = URI.create(origin);
            if (parsed.getScheme() == null || parsed.getHost() == null) {
                return origin + "/";
            }
            return new URI(base.getScheme(), parsed.getUserInfo(), base.getHost(), base.getPort(),
                    parsed.getRawPath(), parsed.getRawQuery(), parsed.getRawFragment()).toString();
        } catch (Exception ignored) {
            return origin + "/";
        }
    }

    private static boolean shouldForward(String name) {
        return name != null && !SKIPPED_HEADERS.contains(name.toLowerCase(Locale.ROOT));
    }

    private static String firstHeader(List<String> headers, String name) {
        for (String header : headers) {
            int separator = header.indexOf(':');
            if (separator > 0 && name.equalsIgnoreCase(header.substring(0, separator))) {
                return header.substring(separator + 1);
            }
        }
        return "";
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

    private static List<String> validTrailerNames(List<String> names) {
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

    private static void appendTrailers(HttpHeaders target, List<String> trailers,
                                       List<String> declaredNames) {
        Set<String> declared = new HashSet<>();
        declaredNames.forEach(name -> declared.add(name.toLowerCase(Locale.ROOT)));
        for (String trailer : trailers) {
            int separator = trailer.indexOf(':');
            if (separator <= 0) continue;
            String name = trailer.substring(0, separator).trim();
            String value = trailer.substring(separator + 1).trim();
            if (declared.contains(name.toLowerCase(Locale.ROOT))
                    && isHeaderName(name) && shouldForward(name) && safeHeaderValue(value)) {
                target.add(name, value);
            }
        }
    }

    private static List<String> declaredTrailerNames(HttpHeaders headers) {
        List<String> names = new ArrayList<>();
        for (String declaration : headers.getAll(HttpHeaderNames.TRAILER)) {
            names.addAll(Arrays.asList(declaration.split(",")));
        }
        return validTrailerNames(names);
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

    private static IOException eventError(UpstreamEvent event, String fallback) {
        return event instanceof ResponseError error
                ? new IOException(error.cause().getMessage() == null ? fallback : error.cause().getMessage(), error.cause())
                : new IOException(fallback);
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof Iterable<?> values)) return List.of();
        List<String> result = new ArrayList<>();
        for (Object item : values) if (item != null) result.add(item.toString());
        return result;
    }

    private static String text(Object value) {
        return value == null ? null : value.toString();
    }

    private static long number(Object value, long fallback) {
        if (value instanceof Number number) return number.longValue();
        if (value != null) {
            try {
                return Long.parseLong(value.toString());
            } catch (NumberFormatException ignored) {
            }
        }
        return fallback;
    }

    private sealed interface UpstreamEvent permits ResponseHead, ResponseData, ResponseEnd, ResponseError { }
    private record ResponseHead(int statusCode, List<String> headers,
                                List<String> trailerNames) implements UpstreamEvent { }
    private record ResponseData(byte[] bytes) implements UpstreamEvent { }
    private record ResponseEnd(List<String> trailers) implements UpstreamEvent { }
    private record ResponseError(Throwable cause) implements UpstreamEvent { }

    private static final class UpstreamExchange {
        private final LinkedBlockingQueue<UpstreamEvent> events = new LinkedBlockingQueue<>();
        private final AtomicBoolean terminal = new AtomicBoolean();
        private volatile Channel channel;

        private void bind(Channel channel) {
            this.channel = channel;
        }

        private Channel channel() {
            Channel current = channel;
            if (current == null) throw new IllegalStateException("upstream HTTP channel is not connected");
            return current;
        }

        private void emit(UpstreamEvent event) {
            if (!terminal.get()) events.offer(event);
        }

        private void finish(List<String> trailers) {
            if (terminal.compareAndSet(false, true)) {
                events.offer(new ResponseEnd(List.copyOf(trailers)));
            }
        }

        private void fail(Throwable cause) {
            if (terminal.compareAndSet(false, true)) {
                events.offer(new ResponseError(cause));
            }
        }

        private UpstreamEvent take() throws InterruptedException {
            UpstreamEvent event = events.take();
            if (!(event instanceof ResponseEnd) && !(event instanceof ResponseError)) {
                Channel current = channel;
                if (current != null && current.isActive()) current.read();
            }
            return event;
        }

        private void close() {
            Channel current = channel;
            if (current != null) current.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
        }
    }

    private static final class UpstreamResponseHandler extends SimpleChannelInboundHandler<HttpObject> {
        private final UpstreamExchange exchange;
        private boolean responseStarted;
        private boolean informational;

        private UpstreamResponseHandler(UpstreamExchange exchange) {
            this.exchange = exchange;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, HttpObject message) {
            if (message instanceof HttpResponse response) {
                HttpResponseStatus status = response.status();
                informational = status.code() >= 100 && status.code() < 200 && status.code() != 101;
                if (!informational) {
                    if (responseStarted) {
                        exchange.fail(new IOException("duplicate upstream HTTP response head"));
                        ctx.close();
                        return;
                    }
                    responseStarted = true;
                    exchange.emit(new ResponseHead(status.code(), flattenHeaders(response.headers()),
                            declaredTrailerNames(response.headers())));
                }
            }
            if (message instanceof HttpContent content) {
                if (informational) {
                    if (message instanceof LastHttpContent) informational = false;
                    ctx.read();
                    return;
                }
                if (!responseStarted) {
                    exchange.fail(new IOException("upstream HTTP content arrived before response head"));
                    ctx.close();
                    return;
                }
                if (content.content().isReadable()) {
                    byte[] bytes = new byte[content.content().readableBytes()];
                    content.content().getBytes(content.content().readerIndex(), bytes);
                    exchange.emit(new ResponseData(bytes));
                }
                if (message instanceof LastHttpContent last) {
                    exchange.finish(flattenHeaders(last.trailingHeaders()));
                }
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            exchange.fail(new IOException("upstream HTTP connection closed"));
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            exchange.fail(cause);
            ctx.close();
        }
    }

    private static final class StreamingBodyInput extends InputStream {
        private final ArrayBlockingQueue<Chunk> queue = new ArrayBlockingQueue<>(32);
        private final java.util.function.IntConsumer consumed;
        private Chunk current;
        private int offset;
        private int total;
        private volatile List<String> trailers = List.of();
        private volatile boolean closed;

        private StreamingBodyInput(java.util.function.IntConsumer consumed) {
            this.consumed = consumed;
        }

        private boolean offer(byte[] data) {
            if (closed || data == null || data.length == 0 || total > MAX_REQUEST_BYTES - data.length) {
                return false;
            }
            total += data.length;
            return queue.offer(new Chunk(data, null, List.of(), false));
        }

        private boolean finish(List<String> trailers) {
            if (closed) return false;
            closed = true;
            if (!queue.offer(new Chunk(null, null, List.copyOf(trailers), true))) {
                abort("HTTP request queue full on FIN");
                return false;
            }
            return true;
        }

        private void abort(String reason) {
            closed = true;
            queue.clear();
            queue.offer(new Chunk(null, reason == null ? "HTTP stream reset" : reason, List.of(), false));
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int read = read(one, 0, 1);
            return read < 0 ? -1 : Byte.toUnsignedInt(one[0]);
        }

        @Override
        public int read(byte[] target, int targetOffset, int length) throws IOException {
            if (length == 0) return 0;
            while (current == null || current.data == null || offset == current.data.length) {
                if (current != null && current.data != null) {
                    consumed.accept(current.data.length);
                }
                try {
                    current = queue.take();
                    offset = 0;
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    throw new IOException("HTTP request body interrupted", error);
                }
                if (current.end) {
                    trailers = current.trailers;
                    return -1;
                }
                if (current.error != null) throw new IOException(current.error);
            }
            int copied = Math.min(length, current.data.length - offset);
            System.arraycopy(current.data, offset, target, targetOffset, copied);
            offset += copied;
            return copied;
        }

        private void closeQuietly() {
            closed = true;
            queue.clear();
            queue.offer(new Chunk(null, null, List.of(), true));
        }

        private List<String> trailers() {
            return trailers;
        }

        private record Chunk(byte[] data, String error, List<String> trailers, boolean end) { }
    }
}
