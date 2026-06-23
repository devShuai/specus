package com.theshuai.tunnelserver.http;

import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.tunnelserver.http.DirectHttpDispatcher.DirectHttpTunnelException;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.service.ClientAccountService;
import com.theshuai.tunnelserver.management.service.TrafficInspectionService;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/http")
@Slf4j
public class HttpTunnelController {
    private static final Set<String> SKIPPED_HEADERS = Set.of(
            "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"
    );

    private final DirectHttpDispatcher dispatcher;
    private final TrafficUsageService trafficUsageService;
    private final TrafficInspectionService trafficInspectionService;
    private final ResponseRewriter responseRewriter;
    private final ClientAccountService clientAccountService;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final long timeoutMillis;
    private final int maxRequestBodySize;

    public HttpTunnelController(DirectHttpDispatcher dispatcher,
                                TrafficUsageService trafficUsageService,
                                TrafficInspectionService trafficInspectionService,
                                ResponseRewriter responseRewriter,
                                ClientAccountService clientAccountService,
                                HttpRouteMappingRepository httpRouteMappingRepository,
                                @Value("${tunnel.http.timeout-ms:30000}") long timeoutMillis,
                                @Value("${tunnel.http.max-request-body-size:16777216}") int maxRequestBodySize) {
        this.dispatcher = dispatcher;
        this.trafficUsageService = trafficUsageService;
        this.trafficInspectionService = trafficInspectionService;
        this.responseRewriter = responseRewriter;
        this.clientAccountService = clientAccountService;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.timeoutMillis = timeoutMillis;
        this.maxRequestBodySize = maxRequestBodySize;
    }

    @RequestMapping("/{clientName}/{route}/**")
    public ResponseEntity<byte[]> forward(@PathVariable String clientName,
                                          @PathVariable String route,
                                          @RequestBody(required = false) byte[] body,
                                          HttpServletRequest request) {
        byte[] requestBody = body == null ? new byte[0] : body;
        long startedAt = System.currentTimeMillis();
        String relativePath = relativePath(request);
        List<String> forwardedHeaders = requestHeaders(request);
        log.info("[http-direct][server-ingress] clientName={} method={} route={} path={} queryPresent={} bodyBytes={}",
                clientName, request.getMethod(), route, relativePath,
                request.getQueryString() != null, requestBody.length);
        if (requestBody.length > maxRequestBodySize) {
            log.warn("[http-direct][server-ingress] clientName={} method={} route={} rejected=body-too-large bodyBytes={} maxBodyBytes={}",
                    clientName, request.getMethod(), route, requestBody.length, maxRequestBodySize);
            ResponseEntity<byte[]> errorResponse = error(413, "HTTP 请求体超过限制");
            trafficInspectionService.recordHttpExchange(clientName, route, request.getMethod(), relativePath,
                    request.getQueryString(), forwardedHeaders, requestBody, 413, plainErrorHeaders(),
                    errorResponse.getBody(), startedAt, remoteAddress(request), "HTTP 请求体超过限制");
            return errorResponse;
        }

        DirectHttpRequestPacket packet = new DirectHttpRequestPacket();
        packet.setRequestMethod(request.getMethod());
        packet.setRoute(route);
        packet.setRelativePath(relativePath);
        packet.setRawQuery(request.getQueryString());
        packet.setHeaders(forwardedHeaders);
        packet.setBody(requestBody);

        try {
            DirectHttpResponsePacket response = dispatcher.forward(clientName, packet, timeoutMillis);
            trafficUsageService.recordHttpUpload(clientName, route, requestBody.length);
            byte[] responseBody = response.getBody() == null ? new byte[0] : response.getBody();
            trafficUsageService.recordHttpDownload(clientName, route, responseBody.length);
            if (response.getError() != null) {
                log.warn("[http-direct][server-egress] requestId={} clientName={} status={} error={} elapsedMs={}",
                        response.getRequestId(), clientName, response.getStatusCode(), response.getError(),
                        System.currentTimeMillis() - startedAt);
                int statusCode = response.getStatusCode() > 0 ? response.getStatusCode() : 502;
                ResponseEntity<byte[]> errorResponse = error(statusCode, response.getError());
                trafficInspectionService.recordHttpExchange(clientName, route, request.getMethod(), relativePath,
                        request.getQueryString(), forwardedHeaders, requestBody, statusCode, plainErrorHeaders(),
                        errorResponse.getBody(), startedAt, remoteAddress(request), response.getError());
                return errorResponse;
            }

            HttpHeaders headers = new HttpHeaders();
            // 路径改写：仅当路由开启时生效。改写成功后需要剥离 Content-Encoding/Content-Length，
            // 让 Spring/Tomcat 按实际字节重新计算 Content-Length（Tomcat 不会主动重压缩）。
            List<String> responseHeaders = response.getHeaders();
            boolean rewritten = false;
            if (isPathRewriteEnabled(clientName, route)) {
                Optional<byte[]> maybeRewritten = responseRewriter.rewrite(responseBody, clientName, route, responseHeaders);
                if (maybeRewritten.isPresent()) {
                    responseBody = maybeRewritten.get();
                    responseHeaders = stripEncodingHeaders(responseHeaders);
                    rewritten = true;
                }
            }
            copyHeaders(responseHeaders, headers);
            log.info("[http-direct][server-egress] requestId={} clientName={} status={} bodyBytes={} rewritten={} elapsedMs={}",
                    response.getRequestId(), clientName, response.getStatusCode(), responseBody.length, rewritten,
                    System.currentTimeMillis() - startedAt);
            trafficInspectionService.recordHttpExchange(clientName, route, request.getMethod(), relativePath,
                    request.getQueryString(), forwardedHeaders, requestBody, response.getStatusCode(),
                    response.getHeaders(), responseBody, startedAt, remoteAddress(request), null);
            return ResponseEntity.status(response.getStatusCode()).headers(headers).body(responseBody);
        } catch (DirectHttpTunnelException e) {
            log.warn("[http-direct][server-egress] clientName={} method={} route={} status={} error={} elapsedMs={}",
                    clientName, request.getMethod(), route, e.getStatusCode(), e.getMessage(),
                    System.currentTimeMillis() - startedAt);
            int statusCode = e.getStatusCode() > 0 ? e.getStatusCode() : 502;
            ResponseEntity<byte[]> errorResponse = error(statusCode, e.getMessage());
            trafficInspectionService.recordHttpExchange(clientName, route, request.getMethod(), relativePath,
                    request.getQueryString(), forwardedHeaders, requestBody, statusCode, plainErrorHeaders(),
                    errorResponse.getBody(), startedAt, remoteAddress(request), e.getMessage());
            return errorResponse;
        }
    }

    private String relativePath(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        int clientSeparator = path.indexOf('/', "/http/".length());
        int routeSeparator = clientSeparator < 0 ? -1 : path.indexOf('/', clientSeparator + 1);
        return routeSeparator < 0 ? "/" : path.substring(routeSeparator);
    }

    private List<String> requestHeaders(HttpServletRequest request) {
        List<String> headers = new ArrayList<>();
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            if (!shouldForward(name)) {
                continue;
            }
            Enumeration<String> values = request.getHeaders(name);
            while (values.hasMoreElements()) {
                headers.add(name + ":" + values.nextElement());
            }
        }
        return headers;
    }

    private void copyHeaders(List<String> source, HttpHeaders target) {
        if (source == null) {
            return;
        }
        for (String header : source) {
            int separator = header.indexOf(':');
            if (separator > 0) {
                String name = header.substring(0, separator);
                if (shouldForward(name)) {
                    target.add(name, header.substring(separator + 1));
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

    private ResponseEntity<byte[]> error(int statusCode, String message) {
        return ResponseEntity.status(HttpStatusCode.valueOf(statusCode))
                .header(HttpHeaders.CONTENT_TYPE, "text/plain;charset=UTF-8")
                .body(message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 查路由配置，判断该路由是否开启了响应体路径改写。查询走 JPA cache，开销可控；
     * 任意查询异常一律视为"未开启"，避免改写故障影响主链路。
     */
    private boolean isPathRewriteEnabled(String clientName, String route) {
        try {
            Optional<ClientAccount> account = clientAccountService.findClientByName(clientName);
            if (account.isEmpty()) {
                return false;
            }
            Optional<HttpRouteMapping> mapping = httpRouteMappingRepository
                    .findByClientIdAndRoute(account.get().getId(), route);
            return mapping.map(m -> Boolean.TRUE.equals(m.getPathRewriteEnabled())).orElse(false);
        } catch (RuntimeException e) {
            log.debug("[http-direct] isPathRewriteEnabled lookup failed clientName={} route={} error={}",
                    clientName, route, e.toString());
            return false;
        }
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
}
