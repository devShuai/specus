package com.theshuai.specusserver.http;

import com.theshuai.specusserver.management.service.HttpShareService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Public entry of temporary HTTP shares: {@code ANY /http-share/{shareId}/**}. Every request is
 * decided by {@link HttpShareService#authorizeVisitor} against the database before its body is read
 * or a NAT stream is opened; admitted requests are forwarded by {@link HttpSpecusController} with
 * the route's semantics. Unlike {@code /http/}, a route without a server record is never public
 * here. WebSocket upgrades on this path are claimed by {@link WebSocketSpecusConfig}.
 */
@RestController
public class HttpShareController {
    private final HttpShareService shareService;
    private final HttpSpecusController forwarder;

    public HttpShareController(HttpShareService shareService, HttpSpecusController forwarder) {
        this.shareService = shareService;
        this.forwarder = forwarder;
    }

    @RequestMapping({"/http-share", "/http-share/**"})
    public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpShareService.VisitorDecision decision = shareService.authorizeVisitor(
                request.getMethod(),
                request.getRequestURI().substring(request.getContextPath().length()),
                request.getQueryString(),
                cookieHeaders(request),
                isWebSocketUpgrade(request));
        if (decision instanceof HttpShareService.Refusal refusal) {
            writeRefusal(response, refusal);
            return;
        }
        HttpShareService.Admission admission = (HttpShareService.Admission) decision;
        try {
            forwarder.forwardShare(admission, request, response);
        } finally {
            admission.stream().release();
        }
    }

    static List<String> cookieHeaders(HttpServletRequest request) {
        List<String> values = new ArrayList<>();
        var headers = request.getHeaders(HttpHeaders.COOKIE);
        if (headers != null) {
            values.addAll(Collections.list(headers));
        }
        return values;
    }

    /** The same detection as the WebSocket mapping of the route entry: {@code Upgrade: websocket}. */
    static boolean isWebSocketUpgrade(HttpServletRequest request) {
        String upgrade = request.getHeader(HttpHeaders.UPGRADE);
        return upgrade != null && upgrade.trim().equalsIgnoreCase("websocket");
    }

    /** A share-path refusal: {@code {"code": ...}}, never cached; the 308 carries no body. */
    static void writeRefusal(HttpServletResponse response, HttpShareService.Refusal refusal) throws IOException {
        response.setStatus(refusal.status());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        for (Map.Entry<String, String> header : refusal.headers().entrySet()) {
            response.addHeader(header.getKey(), header.getValue());
        }
        if (refusal.code() != null) {
            byte[] body = codeBody(refusal.code());
            response.setContentType("application/json");
            response.setContentLength(body.length);
            response.getOutputStream().write(body);
        }
    }

    static byte[] codeBody(String code) {
        // Codes are fixed upper-case identifiers from HttpShareRules: no escaping is needed.
        return ("{\"code\":\"" + code + "\"}").getBytes(StandardCharsets.UTF_8);
    }
}
