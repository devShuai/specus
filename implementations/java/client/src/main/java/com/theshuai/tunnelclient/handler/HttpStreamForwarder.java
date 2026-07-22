package com.theshuai.tunnelclient.handler;

import com.theshuai.common.service.ExecuteService;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Flow;
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
    private static final HttpClient HTTP_CLIENT = buildHttpClient();

    private final NatClientHandler owner;
    private final int streamId;
    private final Map<String, Object> metadata;
    private final Map<String, String> routes;
    private final StreamingBodyInput requestBody;
    private final AtomicBoolean remoteReset = new AtomicBoolean();
    private volatile InputStream responseBody;

    HttpStreamForwarder(NatClientHandler owner, int streamId, Map<String, Object> metadata,
                        Map<String, String> routes) {
        this.owner = owner;
        this.streamId = streamId;
        this.metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
        this.routes = routes;
        this.requestBody = new StreamingBodyInput(bytes -> owner.sendHttpWindowUpdate(streamId, bytes));
    }

    void start() {
        ExecuteService.submit(this);
    }

    boolean onData(byte[] data) {
        return requestBody.offer(data);
    }

    void onRequestFin(Map<String, Object> ignoredTrailers) {
        requestBody.finish();
    }

    void cancel(String reason) {
        remoteReset.set(true);
        requestBody.abort(reason);
        InputStream response = responseBody;
        if (response != null) {
            try {
                response.close();
            } catch (IOException ignored) {
            }
        }
    }

    @Override
    public void run() {
        try {
            String method = requiredText("method");
            String route = requiredText("route");
            String relativePath = text(metadata.get("relativePath"));
            String rawQuery = text(metadata.get("rawQuery"));
            URI target = HttpRouteTargetResolver.buildTarget(routes.get(route), relativePath, rawQuery);
            long contentLength = number(metadata.get("contentLength"), -1L);
            HttpRequest.BodyPublisher bodyPublisher = contentLength == 0
                    ? HttpRequest.BodyPublishers.noBody()
                    : new LengthAwareBodyPublisher(
                            HttpRequest.BodyPublishers.ofInputStream(() -> requestBody), contentLength);
            HttpRequest.Builder builder = HttpRequest.newBuilder(target)
                    .method(method, bodyPublisher);
            List<String> headers = stringList(metadata.get("headers"));
            String range = HttpRouteTargetResolver.boundedRange(firstHeader(headers, "range"));
            for (String header : headers) {
                int separator = header.indexOf(':');
                if (separator <= 0) continue;
                String name = header.substring(0, separator);
                if (!shouldForward(name) || (range != null && "range".equalsIgnoreCase(name))) continue;
                builder.header(name, header.substring(separator + 1));
            }
            if (range != null) {
                builder.header("Range", range);
            }

            HttpResponse<InputStream> upstream = HTTP_CLIENT.send(
                    builder.build(), HttpResponse.BodyHandlers.ofInputStream());
            List<String> responseHeaders = flattenHeaders(upstream.headers().map());
            owner.sendHttpResponseHead(streamId, upstream.statusCode(), responseHeaders)
                    .get(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            responseBody = upstream.body();
            long total = 0;
            byte[] buffer = new byte[64 * 1024];
            try (InputStream input = responseBody) {
                for (int read; (read = input.read(buffer)) >= 0; ) {
                    if (read == 0) continue;
                    total += read;
                    if (total > MAX_RESPONSE_BYTES) {
                        throw new IOException("HTTP 响应体超过限制");
                    }
                    owner.sendHttpResponseData(streamId, java.util.Arrays.copyOf(buffer, read))
                            .get(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                }
            }
            owner.finishHttpResponse(streamId, List.of())
                    .get(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
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

    private static HttpClient buildHttpClient() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, new SecureRandom());
            SSLParameters parameters = new SSLParameters();
            parameters.setEndpointIdentificationAlgorithm("");
            return HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .sslContext(context)
                    .sslParameters(parameters)
                    .build();
        } catch (Exception error) {
            throw new ExceptionInInitializerError(error);
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

    private static List<String> flattenHeaders(Map<String, List<String>> headers) {
        List<String> result = new ArrayList<>();
        headers.forEach((name, values) -> {
            if (shouldForward(name)) {
                values.forEach(value -> result.add(name + ":" + value));
            }
        });
        return result;
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

    private record LengthAwareBodyPublisher(HttpRequest.BodyPublisher delegate, long length)
            implements HttpRequest.BodyPublisher {
        @Override public long contentLength() { return length >= 0 ? length : delegate.contentLength(); }
        @Override public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {
            delegate.subscribe(subscriber);
        }
    }

    private static final class StreamingBodyInput extends InputStream {
        private static final Chunk END = new Chunk(null, null);
        private final ArrayBlockingQueue<Chunk> queue = new ArrayBlockingQueue<>(32);
        private final java.util.function.IntConsumer consumed;
        private Chunk current;
        private int offset;
        private int total;
        private volatile boolean closed;

        private StreamingBodyInput(java.util.function.IntConsumer consumed) {
            this.consumed = consumed;
        }

        private boolean offer(byte[] data) {
            if (closed || data == null || data.length == 0 || total > MAX_REQUEST_BYTES - data.length) {
                return false;
            }
            total += data.length;
            return queue.offer(new Chunk(data, null));
        }

        private void finish() {
            queue.offer(END);
        }

        private void abort(String reason) {
            closed = true;
            queue.clear();
            queue.offer(new Chunk(null, reason == null ? "HTTP stream reset" : reason));
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
                if (current == END) return -1;
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
            queue.offer(END);
        }

        private record Chunk(byte[] data, String error) { }
    }
}
