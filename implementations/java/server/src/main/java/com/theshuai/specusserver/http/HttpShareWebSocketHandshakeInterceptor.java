package com.theshuai.specusserver.http;

import com.theshuai.specusserver.httpshare.HttpShareStreamRegistry;
import com.theshuai.specusserver.management.service.HttpShareService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.io.IOException;
import java.util.Map;

/**
 * WebSocket upgrades under {@code /http-share/{shareId}/**}: the same share decision as plain
 * requests (a read-only share refuses every upgrade with 403) before the 101 is answered, then the
 * handshake attributes {@link WebSocketSpecusHandler} turns into the NAT OPEN: the route's current
 * name on its client's current name, the raw relative path, and the request headers without the
 * share cookie. The in-flight slot travels with the session so that the end of the share closes
 * it with 1008.
 */
@Component
@Slf4j
public class HttpShareWebSocketHandshakeInterceptor implements HandshakeInterceptor {
    static final String REQUEST_ATTR_STREAM = HttpShareWebSocketHandshakeInterceptor.class.getName() + ".stream";

    private final HttpShareService shareService;

    public HttpShareWebSocketHandshakeInterceptor(HttpShareService shareService) {
        this.shareService = shareService;
    }

    @Override
    public boolean beforeHandshake(ServerHttpRequest request,
                                   ServerHttpResponse response,
                                   WebSocketHandler wsHandler,
                                   Map<String, Object> attributes) throws IOException {
        if (!(request instanceof ServletServerHttpRequest servletRequest)) {
            log.warn("[http-share][ws] non-servlet request, rejecting");
            return false;
        }
        HttpServletRequest http = servletRequest.getServletRequest();
        HttpShareService.VisitorDecision decision = shareService.authorizeVisitor(
                http.getMethod(),
                http.getRequestURI().substring(http.getContextPath().length()),
                http.getQueryString(),
                HttpShareController.cookieHeaders(http),
                true);
        if (decision instanceof HttpShareService.Refusal refusal) {
            response.setStatusCode(HttpStatusCode.valueOf(refusal.status()));
            response.getHeaders().set(HttpHeaders.CACHE_CONTROL, "no-store");
            refusal.headers().forEach((name, value) -> response.getHeaders().add(name, value));
            if (refusal.code() != null) {
                response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                response.getBody().write(HttpShareController.codeBody(refusal.code()));
            }
            return false;
        }
        HttpShareService.Admission admission = (HttpShareService.Admission) decision;
        attributes.put(WebSocketSpecusHandler.ATTR_CLIENT_NAME, admission.clientName());
        attributes.put(WebSocketSpecusHandler.ATTR_ROUTE, admission.routeName());
        attributes.put(WebSocketSpecusHandler.ATTR_RELATIVE_PATH, admission.relativePath());
        attributes.put(WebSocketSpecusHandler.ATTR_RAW_QUERY,
                HttpQueryStringCodec.encodeForForwarding(http.getQueryString()));
        attributes.put(WebSocketSpecusHandler.ATTR_HEADERS, UpstreamBrowserHeaders.rewrite(
                HttpSpecusController.withoutShareCookie(
                        WebSocketSpecusHandshakeInterceptor.collectHeaders(http, false)),
                admission.targetBaseUrl()));
        attributes.put(WebSocketSpecusHandler.ATTR_BODY, new byte[0]);
        attributes.put(WebSocketSpecusHandler.ATTR_SHARE_STREAM, admission.stream());
        http.setAttribute(REQUEST_ATTR_STREAM, admission.stream());
        return true;
    }

    @Override
    public void afterHandshake(ServerHttpRequest request,
                               ServerHttpResponse response,
                               WebSocketHandler wsHandler,
                               Exception exception) {
        if (!(request instanceof ServletServerHttpRequest servletRequest)) {
            return;
        }
        Object stream = servletRequest.getServletRequest().getAttribute(REQUEST_ATTR_STREAM);
        if (!(stream instanceof HttpShareStreamRegistry.InFlight inFlight)) {
            return;
        }
        int status = response instanceof ServletServerHttpResponse servletResponse
                ? servletResponse.getServletResponse().getStatus() : 0;
        // The upgrade failed after the share admitted it: no session will release the slot.
        if (exception != null || status >= 300) {
            inFlight.release();
        }
    }
}
