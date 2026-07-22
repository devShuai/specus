package com.theshuai.tunnelserver.http;

import com.theshuai.tunnelserver.management.service.TrafficInspectionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class HttpTunnelBodyLimitFilter extends OncePerRequestFilter {
    private static final String TOO_LARGE_MESSAGE = "HTTP 请求体超过限制";
    private static final byte[] BODY_TOO_LARGE = TOO_LARGE_MESSAGE.getBytes(StandardCharsets.UTF_8);
    private static final int REQUEST_CAPTURE_BYTES = 64 * 1024;
    private static final Set<String> SKIPPED_HEADERS = Set.of(
            "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"
    );

    private final int maxRequestBodySize;
    private final TrafficInspectionService trafficInspectionService;

    public HttpTunnelBodyLimitFilter(
            @Value("${tunnel.http.max-request-body-size:16777216}") int maxRequestBodySize,
            TrafficInspectionService trafficInspectionService) {
        this.maxRequestBodySize = Math.max(0, maxRequestBodySize);
        this.trafficInspectionService = trafficInspectionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (isHttpTunnelRequest(request) && request.getContentLengthLong() > maxRequestBodySize) {
            long startedAt = System.currentTimeMillis();
            byte[] requestCapture = captureRequestPrefix(request);
            response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            response.setContentType("text/plain;charset=UTF-8");
            response.setContentLength(BODY_TOO_LARGE.length);
            response.getOutputStream().write(BODY_TOO_LARGE);
            recordTooLargeExchange(request, startedAt, requestCapture);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean isHttpTunnelRequest(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return path.startsWith("/http/");
    }

    private void recordTooLargeExchange(HttpServletRequest request, long startedAt, byte[] requestCapture) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        String remainder = path.substring("/http/".length());
        int clientSeparator = remainder.indexOf('/');
        String clientName = clientSeparator < 0 ? remainder : remainder.substring(0, clientSeparator);
        String route = "";
        if (clientSeparator >= 0) {
            String afterClient = remainder.substring(clientSeparator + 1);
            int routeSeparator = afterClient.indexOf('/');
            route = routeSeparator < 0 ? afterClient : afterClient.substring(0, routeSeparator);
        }
        int pathClientSeparator = path.indexOf('/', "/http/".length());
        int pathRouteSeparator = pathClientSeparator < 0 ? -1 : path.indexOf('/', pathClientSeparator + 1);
        String relativePath = pathRouteSeparator < 0 ? "/" : path.substring(pathRouteSeparator);
        trafficInspectionService.recordHttpExchange(clientName, route, request.getMethod(), relativePath,
                request.getQueryString(), requestHeaders(request), requestCapture,
                HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                List.of(HttpHeaders.CONTENT_TYPE + ":text/plain;charset=UTF-8"),
                BODY_TOO_LARGE, startedAt,
                request.getRemoteAddr() + ":" + request.getRemotePort(), TOO_LARGE_MESSAGE);
    }

    private byte[] captureRequestPrefix(HttpServletRequest request) throws IOException {
        int captureSize = (int) Math.min(REQUEST_CAPTURE_BYTES, (long) maxRequestBodySize + 1);
        if (captureSize <= 0) {
            return new byte[0];
        }
        ByteArrayOutputStream capture = new ByteArrayOutputStream(captureSize);
        byte[] chunk = new byte[Math.min(captureSize, 8192)];
        int remaining = captureSize;
        try (InputStream input = request.getInputStream()) {
            while (remaining > 0) {
                int read = input.read(chunk, 0, Math.min(chunk.length, remaining));
                if (read < 0) {
                    break;
                }
                capture.write(chunk, 0, read);
                remaining -= read;
            }
        }
        return capture.toByteArray();
    }

    private List<String> requestHeaders(HttpServletRequest request) {
        List<String> headers = new ArrayList<>();
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            if (SKIPPED_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                continue;
            }
            Enumeration<String> values = request.getHeaders(name);
            while (values.hasMoreElements()) {
                headers.add(name + ":" + values.nextElement());
            }
        }
        return headers;
    }
}
