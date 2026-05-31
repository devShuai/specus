package com.theshuai.tunnelserver.http;

import com.theshuai.common.manager.DirectHttpFutureManager;
import com.theshuai.common.manager.DirectHttpFutureManager.DirectHttpTunnelException;
import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import jakarta.servlet.http.HttpServletRequest;
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
import java.util.Set;

@RestController
@RequestMapping("/http")
public class HttpTunnelController {
    private static final Set<String> SKIPPED_HEADERS = Set.of(
            "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"
    );

    private final TrafficUsageService trafficUsageService;
    private final long timeoutMillis;
    private final int maxRequestBodySize;

    public HttpTunnelController(TrafficUsageService trafficUsageService,
                                @Value("${tunnel.http.timeout-ms:30000}") long timeoutMillis,
                                @Value("${tunnel.http.max-request-body-size:16777216}") int maxRequestBodySize) {
        this.trafficUsageService = trafficUsageService;
        this.timeoutMillis = timeoutMillis;
        this.maxRequestBodySize = maxRequestBodySize;
    }

    @RequestMapping("/{clientName}/{route}/**")
    public ResponseEntity<byte[]> forward(@PathVariable String clientName,
                                          @PathVariable String route,
                                          @RequestBody(required = false) byte[] body,
                                          HttpServletRequest request) {
        byte[] requestBody = body == null ? new byte[0] : body;
        if (requestBody.length > maxRequestBodySize) {
            return error(413, "HTTP 请求体超过限制");
        }

        DirectHttpRequestPacket packet = new DirectHttpRequestPacket();
        packet.setRequestMethod(request.getMethod());
        packet.setRoute(route);
        packet.setRelativePath(relativePath(request));
        packet.setRawQuery(request.getQueryString());
        packet.setHeaders(requestHeaders(request));
        packet.setBody(requestBody);

        try {
            DirectHttpResponsePacket response = DirectHttpFutureManager.forward(clientName, packet, timeoutMillis);
            trafficUsageService.recordUpload(clientName, requestBody.length);
            byte[] responseBody = response.getBody() == null ? new byte[0] : response.getBody();
            trafficUsageService.recordDownload(clientName, responseBody.length);
            if (response.getError() != null) {
                return error(response.getStatusCode() > 0 ? response.getStatusCode() : 502, response.getError());
            }

            HttpHeaders headers = new HttpHeaders();
            copyHeaders(response.getHeaders(), headers);
            return ResponseEntity.status(response.getStatusCode()).headers(headers).body(responseBody);
        } catch (DirectHttpTunnelException e) {
            return error(e.getStatusCode(), e.getMessage());
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

    private ResponseEntity<byte[]> error(int statusCode, String message) {
        return ResponseEntity.status(HttpStatusCode.valueOf(statusCode))
                .header(HttpHeaders.CONTENT_TYPE, "text/plain;charset=UTF-8")
                .body(message.getBytes(StandardCharsets.UTF_8));
    }
}
