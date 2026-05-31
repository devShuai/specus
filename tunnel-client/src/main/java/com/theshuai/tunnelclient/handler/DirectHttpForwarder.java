package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.util.Timeout;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Slf4j
public final class DirectHttpForwarder {
    private static final int MAX_REQUEST_BODY_SIZE = 16 * 1024 * 1024;
    private static final int MAX_RESPONSE_BODY_SIZE = 16 * 1024 * 1024;
    private static final Timeout CONNECTION_REQUEST_TIMEOUT = Timeout.ofSeconds(5);
    private static final Timeout CONNECT_TIMEOUT = Timeout.ofSeconds(5);
    private static final Timeout RESPONSE_TIMEOUT = Timeout.ofSeconds(20);
    private static final CloseableHttpClient HTTP_CLIENT = HttpClients.custom()
            .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                    .setDefaultConnectionConfig(ConnectionConfig.custom()
                            .setConnectTimeout(CONNECT_TIMEOUT)
                            .setSocketTimeout(RESPONSE_TIMEOUT)
                            .build())
                    .build())
            .disableContentCompression()
            .disableRedirectHandling()
            .build();
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
            copyHeaders(packet.getHeaders(), request::addHeader);
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

    private static boolean shouldForward(String name) {
        return name != null && !SKIPPED_HEADERS.contains(name.toLowerCase(Locale.ROOT));
    }

    @FunctionalInterface
    private interface HeaderConsumer {
        void accept(String name, String value);
    }
}
