package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.util.Timeout;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Slf4j
public final class DirectHttpForwarder {
    private static final int MAX_REQUEST_BODY_SIZE = 16 * 1024 * 1024;
    private static final int MAX_RESPONSE_BODY_SIZE = 64 * 1024 * 1024;
    private static final long MAX_RANGE_BYTES = 8L * 1024 * 1024;
    private static final Timeout CONNECTION_REQUEST_TIMEOUT = Timeout.ofSeconds(5);
    private static final Timeout CONNECT_TIMEOUT = Timeout.ofSeconds(5);
    private static final Timeout RESPONSE_TIMEOUT = Timeout.ofSeconds(20);

    /** 信任所有证书的 SSLContext —— 内网穿透场景下客户端→本地目标通常是同一内网，无需校验。 */
    private static final SSLContext TRUST_ALL_SSL;
    static {
        try {
            TRUST_ALL_SSL = SSLContext.getInstance("TLS");
            TRUST_ALL_SSL.init(null, new TrustManager[]{new TrustAllX509TrustManager()}, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException("Failed to initialize trust-all SSLContext", e);
        }
    }

    private static final CloseableHttpClient HTTP_CLIENT = HttpClients.custom()
            .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                    .setDefaultConnectionConfig(ConnectionConfig.custom()
                            .setConnectTimeout(CONNECT_TIMEOUT)
                            .setSocketTimeout(RESPONSE_TIMEOUT)
                            .build())
                    .setTlsSocketStrategy(new DefaultClientTlsStrategy(TRUST_ALL_SSL, null, null,
                            null, HostnameVerificationPolicy.CLIENT, NoopHostnameVerifier.INSTANCE))
                    .build())
            .disableContentCompression()
            .disableRedirectHandling()
            .build();

    /** 不做任何证书校验的 TrustManager。 */
    private static final class TrustAllX509TrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
    private static final Set<String> SKIPPED_HEADERS = Set.of(
            "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"
    );

    private DirectHttpForwarder() {
    }

    public static DirectHttpResponsePacket forward(DirectHttpRequestPacket packet, Map<String, String> routes) {
        DirectHttpResponsePacket response = new DirectHttpResponsePacket();
        response.setRequestId(packet.getRequestId());
        long startedAt = System.currentTimeMillis();
        try {
            if (packet.getBody() != null && packet.getBody().length > MAX_REQUEST_BODY_SIZE) {
                throw new IllegalArgumentException("HTTP 请求体超过限制");
            }
            URI target = buildTarget(routes.get(packet.getRoute()), packet.getRelativePath(), packet.getRawQuery());
            log.info("[http-direct][client->upstream] requestId={} method={} route={} target={} queryPresent={} bodyBytes={} poolTimeoutMs={} connectTimeoutMs={} responseTimeoutMs={}",
                    packet.getRequestId(), packet.getRequestMethod(), packet.getRoute(), withoutQuery(target),
                    target.getRawQuery() != null, size(packet.getBody()), CONNECTION_REQUEST_TIMEOUT.toMilliseconds(),
                    CONNECT_TIMEOUT.toMilliseconds(), RESPONSE_TIMEOUT.toMilliseconds());
            HttpUriRequestBase request = new HttpUriRequestBase(packet.getRequestMethod(), target);
            request.setConfig(RequestConfig.custom()
                    .setConnectionRequestTimeout(CONNECTION_REQUEST_TIMEOUT)
                    .setResponseTimeout(RESPONSE_TIMEOUT)
                    .setRedirectsEnabled(false)
                    .build());
            String originalRange = firstHeader(packet.getHeaders(), "range");
            String boundedRange = boundedRange(originalRange);
            copyHeaders(packet.getHeaders(), (name, value) -> {
                if (boundedRange != null && "range".equalsIgnoreCase(name)) {
                    return;
                }
                request.addHeader(name, value);
            });
            if (boundedRange != null) {
                request.setHeader("Range", boundedRange);
                if (originalRange != null && !originalRange.trim().equalsIgnoreCase(boundedRange)) {
                    log.info("[http-direct][client->upstream] requestId={} range bounded: {} -> {}",
                            packet.getRequestId(), originalRange.trim(), boundedRange);
                }
            }
            if (packet.getBody() != null && packet.getBody().length > 0) {
                request.setEntity(new ByteArrayEntity(packet.getBody(), null));
            }

            return HTTP_CLIENT.execute(request, upstream -> {
                response.setStatusCode(upstream.getCode());
                response.setHeaders(toHeaders(upstream.getHeaders()));
                response.setBody(readBody(upstream.getEntity()));
                log.info("[http-direct][upstream->client] requestId={} status={} bodyBytes={} elapsedMs={}",
                        packet.getRequestId(), response.getStatusCode(), size(response.getBody()),
                        System.currentTimeMillis() - startedAt);
                return response;
            });
        } catch (Exception e) {
            response.setStatusCode(502);
            response.setError(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            log.warn("[http-direct][upstream->client] requestId={} status=502 error={} elapsedMs={}",
                    packet.getRequestId(), response.getError(), System.currentTimeMillis() - startedAt, e);
            return response;
        }
    }

    private static URI withoutQuery(URI target) {
        return URI.create(target.getScheme() + "://" + target.getRawAuthority() + target.getRawPath());
    }

    private static int size(byte[] body) {
        return body == null ? 0 : body.length;
    }

    private static byte[] readBody(HttpEntity entity) throws IOException {
        if (entity == null) {
            return new byte[0];
        }
        if (entity.getContentLength() > MAX_RESPONSE_BODY_SIZE) {
            throw new IOException("HTTP 响应体超过限制");
        }
        byte[] body = EntityUtils.toByteArray(entity, MAX_RESPONSE_BODY_SIZE + 1);
        if (body.length > MAX_RESPONSE_BODY_SIZE) {
            throw new IOException("HTTP 响应体超过限制");
        }
        return body;
    }

    static URI buildTarget(String targetBaseUrl, String relativePath, String rawQuery) {
        if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
            throw new IllegalArgumentException("未配置 HTTP route");
        }
        URI base = URI.create(targetBaseUrl);
        if (!"http".equalsIgnoreCase(base.getScheme()) && !"https".equalsIgnoreCase(base.getScheme())) {
            throw new IllegalArgumentException("HTTP route 仅支持 http 和 https");
        }
        if (base.getHost() == null || base.getRawQuery() != null || base.getRawFragment() != null) {
            throw new IllegalArgumentException("HTTP route 地址无效");
        }

        String path = relativePath == null || relativePath.isBlank() ? "/" : relativePath;
        if (!path.startsWith("/") || path.contains("\r") || path.contains("\n")) {
            throw new IllegalArgumentException("HTTP 转发路径无效");
        }
        String baseUrl = targetBaseUrl.endsWith("/") ? targetBaseUrl.substring(0, targetBaseUrl.length() - 1) : targetBaseUrl;
        URI target = URI.create(baseUrl + path + (rawQuery == null || rawQuery.isBlank() ? "" : "?" + rawQuery));
        if (!base.getScheme().equalsIgnoreCase(target.getScheme())
                || !base.getHost().equalsIgnoreCase(target.getHost())
                || base.getPort() != target.getPort()) {
            throw new IllegalArgumentException("HTTP 转发目标越界");
        }
        String basePath = normalizeBasePath(base.getPath());
        for (String segment : target.getPath().split("/")) {
            if (".".equals(segment) || "..".equals(segment)) {
                throw new IllegalArgumentException("HTTP 转发路径越界");
            }
        }
        String targetPath = target.normalize().getPath();
        if (!"/".equals(basePath) && !targetPath.equals(basePath) && !targetPath.startsWith(basePath + "/")) {
            throw new IllegalArgumentException("HTTP 转发路径越界");
        }
        return target;
    }

    private static String normalizeBasePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        return path.endsWith("/") && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
    }

    private static List<String> toHeaders(Header[] headers) {
        List<String> result = new ArrayList<>();
        for (Header header : headers) {
            if (shouldForward(header.getName())) {
                result.add(header.getName() + ":" + header.getValue());
            }
        }
        return result;
    }

    private static void copyHeaders(List<String> headers, HeaderConsumer consumer) {
        if (headers == null) {
            return;
        }
        for (String header : headers) {
            int separator = header.indexOf(':');
            if (separator > 0) {
                String name = header.substring(0, separator);
                if (shouldForward(name)) {
                    consumer.accept(name, header.substring(separator + 1));
                }
            }
        }
    }

    private static String firstHeader(List<String> headers, String headerName) {
        if (headers == null || headerName == null) {
            return null;
        }
        for (String header : headers) {
            int separator = header.indexOf(':');
            if (separator > 0 && headerName.equalsIgnoreCase(header.substring(0, separator))) {
                return header.substring(separator + 1);
            }
        }
        return null;
    }

    static String boundedRange(String rangeHeader) {
        if (rangeHeader == null) {
            return null;
        }
        String value = rangeHeader.trim();
        if (!value.regionMatches(true, 0, "bytes=", 0, "bytes=".length())) {
            return null;
        }
        String spec = value.substring("bytes=".length()).trim();
        if (spec.isEmpty() || spec.contains(",")) {
            return null;
        }
        int dash = spec.indexOf('-');
        if (dash < 0) {
            return null;
        }

        String startPart = spec.substring(0, dash).trim();
        String endPart = spec.substring(dash + 1).trim();
        try {
            if (startPart.isEmpty()) {
                if (endPart.isEmpty()) {
                    return null;
                }
                long suffixLength = Long.parseLong(endPart);
                if (suffixLength <= 0) {
                    return null;
                }
                return "bytes=-" + Math.min(suffixLength, MAX_RANGE_BYTES);
            }

            long start = Long.parseLong(startPart);
            if (start < 0) {
                return null;
            }
            long maxEnd = boundedEnd(start);
            if (endPart.isEmpty()) {
                return "bytes=" + start + "-" + maxEnd;
            }
            long end = Long.parseLong(endPart);
            if (end < start) {
                return null;
            }
            return "bytes=" + start + "-" + Math.min(end, maxEnd);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static long boundedEnd(long start) {
        long delta = MAX_RANGE_BYTES - 1;
        if (Long.MAX_VALUE - start < delta) {
            return Long.MAX_VALUE;
        }
        return start + delta;
    }

    private static boolean shouldForward(String name) {
        return name != null && !SKIPPED_HEADERS.contains(name.toLowerCase(Locale.ROOT));
    }

    @FunctionalInterface
    private interface HeaderConsumer {
        void accept(String name, String value);
    }
}
