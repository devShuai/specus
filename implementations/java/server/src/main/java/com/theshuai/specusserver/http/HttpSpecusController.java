package com.theshuai.specusserver.http;

import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.handler.SpecusStreamIds;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.HttpMediaCaptureService;
import com.theshuai.specusserver.management.service.HttpMediaCaptureService.CaptureSession;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@RestController
@RequestMapping("/http")
@Slf4j
public class HttpSpecusController {
    private static final Set<String> SKIPPED_HEADERS = Set.of(
            "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"
    );

    private final TrafficUsageService trafficUsageService;
    private final TrafficInspectionService trafficInspectionService;
    private final HttpMediaCaptureService mediaCaptureService;
    private final ResponseRewriter responseRewriter;
    private final ClientAccountService clientAccountService;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final HttpRouteAuthenticationService routeAuthenticationService;
    private final long timeoutMillis;
    private final int maxRequestBodySize;
    private final long routeCacheTtlMillis;
    private final ConcurrentMap<String, RewriteDecision> rewriteDecisionCache = new ConcurrentHashMap<>();

    public HttpSpecusController(TrafficUsageService trafficUsageService,
                                TrafficInspectionService trafficInspectionService,
                                HttpMediaCaptureService mediaCaptureService,
                                ResponseRewriter responseRewriter,
                                ClientAccountService clientAccountService,
                                HttpRouteMappingRepository httpRouteMappingRepository,
                                HttpRouteAuthenticationService routeAuthenticationService,
                                @Value("${specus.http.timeout-ms:30000}") long timeoutMillis,
                                @Value("${specus.http.max-request-body-size:16777216}") int maxRequestBodySize,
                                @Value("${specus.http.route-cache-ttl-ms:2000}") long routeCacheTtlMillis) {
        this.trafficUsageService = trafficUsageService;
        this.trafficInspectionService = trafficInspectionService;
        this.mediaCaptureService = mediaCaptureService;
        this.responseRewriter = responseRewriter;
        this.clientAccountService = clientAccountService;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.routeAuthenticationService = routeAuthenticationService;
        this.timeoutMillis = timeoutMillis;
        this.maxRequestBodySize = maxRequestBodySize;
        this.routeCacheTtlMillis = Math.max(0, routeCacheTtlMillis);
    }

    @RequestMapping("/{clientName}/{route}/**")
    public void forward(@PathVariable String clientName,
                        @PathVariable String route,
                        HttpServletRequest request,
                        HttpServletResponse response) throws IOException {
        long startedAt = System.currentTimeMillis();
        String relativePath = relativePath(request);
        List<String> forwardedHeaders = List.of();
        FullCapture requestCapture = new FullCapture(false);
        FullCapture responseCapture = new FullCapture(false);
        long requestBytes = 0;
        long responseBytes = 0;
        int statusCode = 502;
        List<String> responseHeaders = plainErrorHeaders();
        String failure = null;
        NatServerHandler natHandler = null;
        HttpStreamExchange exchange = null;
        CaptureSession mediaCapture = CaptureSession.noop();
        boolean responseBodyExternalized = false;
        boolean opened = false;
        try {
            HttpRouteAuthenticationService.Decision access = routeAuthenticationService.authorize(
                    clientName, route, request.getHeader(HttpHeaders.AUTHORIZATION));
            switch (access.outcome()) {
                case UNAUTHORIZED -> {
                    response.setHeader(HttpHeaders.WWW_AUTHENTICATE,
                            HttpRouteAuthenticationService.BASIC_CHALLENGE);
                    response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
                    throw new HttpForwardFailure(401, "需要 HTTP Basic 认证");
                }
                case NOT_FOUND -> {
                    response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
                    throw new HttpForwardFailure(404, "HTTP 路由不存在或未启用");
                }
                case UNAVAILABLE -> {
                    response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
                    throw new HttpForwardFailure(503, "HTTP 路由认证暂不可用");
                }
                default -> {
                    // PUBLIC and AUTHENTICATED continue into the data plane.
                }
            }
            forwardedHeaders = UpstreamBrowserHeaders.rewrite(
                    requestHeaders(request, access.credentialsConsumed()),
                    targetBaseUrl(clientName, route));
            boolean detailCaptureEnabled = trafficInspectionService.shouldCaptureHttpExchange(clientName, route);
            requestCapture = new FullCapture(detailCaptureEnabled);
            responseCapture = new FullCapture(detailCaptureEnabled);

            Channel control = SessionUtil.getDataChannel(clientName);
            natHandler = control == null ? null : control.pipeline().get(NatServerHandler.class);
            if (natHandler == null || !control.isActive()) {
                throw new HttpForwardFailure(502, "客户端不在线");
            }
            int streamId = SpecusStreamIds.next();
            exchange = new HttpStreamExchange(streamId);
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("source", "http");
            metadata.put("phase", "request");
            metadata.put("requestId", Integer.toUnsignedString(streamId));
            metadata.put("method", request.getMethod());
            metadata.put("route", route);
            metadata.put("relativePath", relativePath);
            metadata.put("rawQuery", request.getQueryString());
            metadata.put("headers", forwardedHeaders);
            List<String> requestTrailerNames = declaredTrailerNames(
                    request.getHeaders("Trailer"), access.credentialsConsumed());
            if (!requestTrailerNames.isEmpty()) {
                metadata.put("trailerNames", requestTrailerNames);
            }
            if (request.getContentLengthLong() >= 0) {
                metadata.put("contentLength", request.getContentLengthLong());
            }
            if (!natHandler.openHttpStream(exchange, metadata)) {
                throw new HttpForwardFailure(502, "HTTP 流创建失败");
            }
            opened = true;

            byte[] chunk = new byte[64 * 1024];
            try (InputStream input = request.getInputStream()) {
                for (int read; (read = input.read(chunk)) >= 0; ) {
                    if (read == 0) continue;
                    requestBytes += read;
                    if (requestBytes > maxRequestBodySize) {
                        throw new HttpForwardFailure(413, "HTTP 请求体超过限制");
                    }
                    byte[] payload = java.util.Arrays.copyOf(chunk, read);
                    requestCapture.append(payload);
                    natHandler.sendHttpData(streamId, payload).get(timeoutMillis, TimeUnit.MILLISECONDS);
                }
            }
            natHandler.finishHttpRequest(streamId, flattenTrailers(
                    request.getTrailerFields(), access.credentialsConsumed(), requestTrailerNames))
                    .get(timeoutMillis, TimeUnit.MILLISECONDS);

            HttpStreamExchange.ResponseHead head = exchange.awaitResponseHead(timeoutMillis);
            statusCode = head.statusCode();
            responseHeaders = head.headers();
            mediaCapture = mediaCaptureService.open(
                    clientName,
                    route,
                    request.getMethod(),
                    sourceUrl(relativePath, request.getQueryString()),
                    statusCode,
                    responseHeaders);
            responseBodyExternalized = mediaCapture.externalized();
            response.setStatus(statusCode);
            List<String> responseTrailerNames = validTrailerNames(head.trailerNames(), false);
            HttpStreamExchange finalExchange = exchange;
            response.setTrailerFields(() -> trailerMap(finalExchange.trailers(), responseTrailerNames));
            if (!responseTrailerNames.isEmpty()) {
                response.setHeader("Trailer", String.join(", ", responseTrailerNames));
            }

            boolean rewriteBuffered = responseRewriter.isRewritableContentType(responseHeaders)
                    && isPathRewriteEnabled(clientName, route)
                    && responseRewriter.maxBodyBytes() > 0;
            ByteArrayOutputStream rewriteBuffer = rewriteBuffered
                    ? new ByteArrayOutputStream(Math.min(64 * 1024, responseRewriter.maxBodyBytes())) : null;
            boolean headersApplied = false;
            if (!rewriteBuffered) {
                copyHeaders(responseHeaders, response);
                headersApplied = true;
            }
            OutputStream output = response.getOutputStream();
            boolean headRequest = "HEAD".equalsIgnoreCase(request.getMethod());
            while (true) {
                HttpStreamExchange.Event event = exchange.take();
                if (event instanceof HttpStreamExchange.Data data) {
                    byte[] bytes = data.bytes();
                    responseBytes += bytes.length;
                    if (!responseBodyExternalized) {
                        responseCapture.append(bytes);
                    }
                    mediaCapture.append(bytes);
                    if (!headRequest) {
                        if (rewriteBuffer != null
                                && rewriteBuffer.size() + bytes.length <= responseRewriter.maxBodyBytes()) {
                            rewriteBuffer.write(bytes);
                        } else {
                            if (rewriteBuffer != null) {
                                copyHeaders(responseHeaders, response);
                                headersApplied = true;
                                rewriteBuffer.writeTo(output);
                                rewriteBuffer = null;
                            }
                            output.write(bytes);
                            output.flush();
                        }
                    }
                    natHandler.consumeHttpResponseData(streamId, bytes.length);
                } else if (event instanceof HttpStreamExchange.Reset reset) {
                    throw new HttpForwardFailure(502, reset.reason());
                } else {
                    break;
                }
            }
            mediaCapture.complete();
            if (rewriteBuffer != null && !headRequest) {
                byte[] original = rewriteBuffer.toByteArray();
                Optional<byte[]> rewritten = responseRewriter.rewrite(original, clientName, route, responseHeaders);
                List<String> finalHeaders = rewritten.isPresent()
                        ? stripEncodingHeaders(responseHeaders) : responseHeaders;
                copyHeaders(finalHeaders, response);
                headersApplied = true;
                output.write(rewritten.orElse(original));
            }
            if (!headersApplied) {
                copyHeaders(responseHeaders, response);
            }
            output.flush();
            log.debug("[http-stream-v2][server-egress] stream={} clientName={} status={} uploadBytes={} downloadBytes={} elapsedMs={}",
                    Integer.toUnsignedString(streamId), clientName, statusCode, requestBytes, responseBytes,
                    System.currentTimeMillis() - startedAt);
        } catch (Exception error) {
            Throwable cause = unwrap(error);
            String errorMessage = cause.getMessage() == null
                    ? cause.getClass().getSimpleName() : cause.getMessage();
            boolean clientDisconnected = response.isCommitted() && isClientDisconnect(cause);
            mediaCapture.fail(errorMessage);
            if (opened && natHandler != null && exchange != null) {
                natHandler.cancelHttpStream(exchange.streamId(), errorMessage);
            }
            if (clientDisconnected) {
                log.debug("[http-stream-v2][server-egress] playback request ended by client clientName={} method={} route={} receivedBytes={} elapsedMs={}",
                        clientName, request.getMethod(), route, responseBytes,
                        System.currentTimeMillis() - startedAt);
            } else {
                int errorStatus = cause instanceof HttpForwardFailure typed ? typed.statusCode :
                        cause instanceof TimeoutException ? 504 : 502;
                failure = errorMessage;
                statusCode = errorStatus;
                responseHeaders = plainErrorHeaders();
                if (!responseBodyExternalized) {
                    responseCapture.append(failure.getBytes(StandardCharsets.UTF_8));
                }
                if (!response.isCommitted()) {
                    writeError(response, errorStatus, failure);
                }
                log.warn("[http-stream-v2][server-egress] clientName={} method={} route={} status={} error={} elapsedMs={}",
                        clientName, request.getMethod(), route, errorStatus, failure,
                        System.currentTimeMillis() - startedAt);
            }
        } finally {
            if (natHandler != null && exchange != null) {
                natHandler.unregisterHttpStream(exchange.streamId());
            }
            trafficUsageService.recordHttpUpload(clientName, route, requestBytes);
            trafficUsageService.recordHttpDownload(clientName, route, responseBytes);
            trafficInspectionService.recordHttpExchange(clientName, route, request.getMethod(), relativePath,
                    request.getQueryString(), forwardedHeaders, requestCapture.bytes(), requestBytes, statusCode,
                    responseHeaders, responseCapture.bytes(), responseBytes, startedAt, remoteAddress(request), failure);
        }
    }

    private String relativePath(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        int clientSeparator = path.indexOf('/', "/http/".length());
        int routeSeparator = clientSeparator < 0 ? -1 : path.indexOf('/', clientSeparator + 1);
        return routeSeparator < 0 ? "/" : path.substring(routeSeparator);
    }

    private String sourceUrl(String relativePath, String rawQuery) {
        return rawQuery == null || rawQuery.isBlank() ? relativePath : relativePath + "?" + rawQuery;
    }

    private List<String> requestHeaders(HttpServletRequest request, boolean stripAuthorization) {
        List<String> headers = new ArrayList<>();
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            if (!shouldForward(name)
                    || stripAuthorization && HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name)) {
                continue;
            }
            Enumeration<String> values = request.getHeaders(name);
            while (values.hasMoreElements()) {
                headers.add(name + ":" + values.nextElement());
            }
        }
        return headers;
    }

    private void copyHeaders(List<String> source, HttpServletResponse target) {
        if (source == null) {
            return;
        }
        for (String header : source) {
            int separator = header.indexOf(':');
            if (separator > 0) {
                String name = header.substring(0, separator);
                if (shouldForward(name)) {
                    target.addHeader(name, header.substring(separator + 1));
                }
            }
        }
    }

    private boolean shouldForward(String name) {
        return name != null && !SKIPPED_HEADERS.contains(name.toLowerCase(Locale.ROOT));
    }

    private List<String> plainErrorHeaders() {
        return List.of(HttpHeaders.CONTENT_TYPE + ":text/plain;charset=UTF-8");
    }

    private String remoteAddress(HttpServletRequest request) {
        return request.getRemoteAddr() + ":" + request.getRemotePort();
    }

    private void writeError(HttpServletResponse response, int statusCode, String message) throws IOException {
        response.resetBuffer();
        response.setStatus(statusCode);
        response.setContentType("text/plain;charset=UTF-8");
        response.getOutputStream().write(message.getBytes(StandardCharsets.UTF_8));
    }

    static List<String> flattenTrailers(Map<String, String> trailers, boolean stripAuthorization) {
        return flattenTrailers(trailers, stripAuthorization,
                trailers == null ? List.of() : List.copyOf(trailers.keySet()));
    }

    static List<String> flattenTrailers(Map<String, String> trailers, boolean stripAuthorization,
                                        List<String> declaredNames) {
        if (trailers == null || trailers.isEmpty()) {
            return List.of();
        }
        Set<String> declared = lowerCaseNames(validTrailerNames(declaredNames, stripAuthorization));
        List<String> result = new ArrayList<>(trailers.size());
        trailers.forEach((name, value) -> {
            if (name != null && value != null
                    && declared.contains(name.toLowerCase(Locale.ROOT))
                    && isHeaderValue(value)) {
                result.add(name + ":" + value);
            }
        });
        return List.copyOf(result);
    }

    static List<String> declaredTrailerNames(Enumeration<String> declarations,
                                             boolean stripAuthorization) {
        List<String> names = new ArrayList<>();
        while (declarations != null && declarations.hasMoreElements()) {
            String declaration = declarations.nextElement();
            if (declaration == null) {
                continue;
            }
            for (String name : declaration.split(",")) {
                names.add(name);
            }
        }
        return validTrailerNames(names, stripAuthorization);
    }

    static List<String> validTrailerNames(List<String> names, boolean stripAuthorization) {
        if (names == null || names.isEmpty()) {
            return List.of();
        }
        Set<String> seen = new java.util.HashSet<>();
        List<String> result = new ArrayList<>();
        for (String candidate : names) {
            String name = candidate == null ? "" : candidate.trim();
            String lower = name.toLowerCase(Locale.ROOT);
            if (isHeaderName(name) && !SKIPPED_HEADERS.contains(lower)
                    && !(stripAuthorization && HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name))
                    && seen.add(lower)) {
                result.add(name);
            }
        }
        return List.copyOf(result);
    }

    private static boolean isHeaderName(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        for (int index = 0; index < name.length(); index++) {
            char ch = name.charAt(index);
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                    || (ch >= '0' && ch <= '9') || "!#$%&'*+-.^_`|~".indexOf(ch) >= 0)) {
                return false;
            }
        }
        return true;
    }

    static Map<String, String> trailerMap(List<String> trailers, List<String> declaredNames) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String trailer : validTrailerLines(trailers, declaredNames)) {
            int separator = trailer.indexOf(':');
            String name = trailer.substring(0, separator).trim();
            String value = trailer.substring(separator + 1).trim();
            result.merge(name, value, (left, right) -> left + "," + right);
        }
        return result;
    }

    static List<String> validTrailerLines(List<String> trailers, List<String> declaredNames) {
        if (trailers == null || trailers.isEmpty()) {
            return List.of();
        }
        Set<String> declared = lowerCaseNames(validTrailerNames(declaredNames, false));
        List<String> result = new ArrayList<>();
        for (String trailer : trailers) {
            if (trailer == null) {
                continue;
            }
            int separator = trailer.indexOf(':');
            if (separator <= 0) {
                continue;
            }
            String name = trailer.substring(0, separator).trim();
            String value = trailer.substring(separator + 1).trim();
            if (declared.contains(name.toLowerCase(Locale.ROOT))
                    && isHeaderName(name) && !SKIPPED_HEADERS.contains(name.toLowerCase(Locale.ROOT))
                    && isHeaderValue(value)) {
                result.add(name + ":" + value);
            }
        }
        return List.copyOf(result);
    }

    private static Set<String> lowerCaseNames(List<String> names) {
        Set<String> result = new java.util.HashSet<>();
        for (String name : names) {
            result.add(name.toLowerCase(Locale.ROOT));
        }
        return result;
    }

    private static boolean isHeaderValue(String value) {
        return value != null && value.indexOf('\r') < 0 && value.indexOf('\n') < 0;
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while (current instanceof ExecutionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static boolean isClientDisconnect(Throwable error) {
        Throwable current = error;
        while (current != null) {
            String className = current.getClass().getSimpleName().toLowerCase(Locale.ROOT);
            String message = current.getMessage() == null
                    ? "" : current.getMessage().toLowerCase(Locale.ROOT);
            if (className.contains("clientabort")
                    || message.contains("broken pipe")
                    || message.contains("connection reset by peer")
                    || message.contains("连接被对方重置")) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    /**
     * 查路由配置，判断该路由是否开启了响应体路径改写。结果短 TTL 缓存，避免每个
     * Spring Boot HTTP 直转请求都额外打两次数据库查询；
     * 任意查询异常一律视为"未开启"，避免改写故障影响主链路。
     */
    private boolean isPathRewriteEnabled(String clientName, String route) {
        String cacheKey = clientName + '\n' + route;
        long now = System.currentTimeMillis();
        RewriteDecision cached = rewriteDecisionCache.get(cacheKey);
        if (cached != null && cached.expiresAtMillis() > now) {
            return cached.enabled();
        }
        boolean enabled = loadPathRewriteEnabled(clientName, route);
        if (routeCacheTtlMillis > 0) {
            rewriteDecisionCache.put(cacheKey, new RewriteDecision(enabled, now + routeCacheTtlMillis));
        }
        return enabled;
    }

    private String targetBaseUrl(String clientName, String route) {
        try {
            Optional<ClientAccount> account = clientAccountService.findClientByName(clientName);
            if (account.isEmpty()) {
                return null;
            }
            return httpRouteMappingRepository.findByClientIdAndRoute(account.get().getId(), route)
                    .map(HttpRouteMapping::getTargetBaseUrl)
                    .orElse(null);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private boolean loadPathRewriteEnabled(String clientName, String route) {
        try {
            Optional<ClientAccount> account = clientAccountService.findClientByName(clientName);
            if (account.isEmpty()) {
                log.debug("[http-direct][rewrite-lookup] clientName={} route={} result=client-not-found",
                        clientName, route);
                return false;
            }
            Optional<HttpRouteMapping> mapping = httpRouteMappingRepository
                    .findByClientIdAndRoute(account.get().getId(), route);
            if (mapping.isEmpty()) {
                log.debug("[http-direct][rewrite-lookup] clientName={} route={} clientId={} result=route-not-found",
                        clientName, route, account.get().getId());
                return false;
            }
            boolean enabled = Boolean.TRUE.equals(mapping.get().getPathRewriteEnabled());
            log.debug("[http-direct][rewrite-lookup] clientName={} route={} pathRewriteEnabled={}",
                    clientName, route, enabled);
            return enabled;
        } catch (RuntimeException e) {
            log.warn("[http-direct][rewrite-lookup] clientName={} route={} error={}",
                    clientName, route, e.toString(), e);
            return false;
        }
    }

    private static String findHeaderValue(List<String> headers, String name) {
        if (headers == null) {
            return null;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        for (String header : headers) {
            if (header == null) continue;
            int sep = header.indexOf(':');
            if (sep > 0 && lower.equals(header.substring(0, sep).trim().toLowerCase(Locale.ROOT))) {
                return header.substring(sep + 1).trim();
            }
        }
        return null;
    }

    /** 改写后剥离 Content-Encoding / Content-Length，让框架按实际字节重新计算并以明文回写。 */
    private List<String> stripEncodingHeaders(List<String> source) {
        if (source == null) {
            return null;
        }
        List<String> result = new ArrayList<>(source.size());
        for (String header : source) {
            if (header == null) {
                continue;
            }
            int separator = header.indexOf(':');
            if (separator > 0) {
                String name = header.substring(0, separator).trim().toLowerCase(Locale.ROOT);
                if (name.equals("content-encoding") || name.equals("content-length")) {
                    continue;
                }
            }
            result.add(header);
        }
        return result;
    }

    private record RewriteDecision(boolean enabled, long expiresAtMillis) {
    }

    private static final class FullCapture {
        private final ByteArrayOutputStream output;

        private FullCapture(boolean enabled) {
            this.output = enabled ? new ByteArrayOutputStream(8192) : null;
        }

        private void append(byte[] bytes) {
            if (output != null && bytes != null && bytes.length > 0) {
                output.write(bytes, 0, bytes.length);
            }
        }

        private byte[] bytes() {
            return output == null ? new byte[0] : output.toByteArray();
        }
    }

    private static final class HttpForwardFailure extends Exception {
        private final int statusCode;

        private HttpForwardFailure(int statusCode, String message) {
            super(message);
            this.statusCode = statusCode;
        }
    }
}
