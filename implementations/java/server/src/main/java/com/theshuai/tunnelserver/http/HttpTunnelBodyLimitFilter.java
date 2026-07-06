package com.theshuai.tunnelserver.http;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class HttpTunnelBodyLimitFilter extends OncePerRequestFilter {
    private static final byte[] BODY_TOO_LARGE =
            "HTTP 请求体超过限制".getBytes(StandardCharsets.UTF_8);

    private final int maxRequestBodySize;

    public HttpTunnelBodyLimitFilter(
            @Value("${tunnel.http.max-request-body-size:16777216}") int maxRequestBodySize) {
        this.maxRequestBodySize = Math.max(0, maxRequestBodySize);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (isHttpTunnelRequest(request) && request.getContentLengthLong() > maxRequestBodySize) {
            response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            response.setContentType("text/plain;charset=UTF-8");
            response.setContentLength(BODY_TOO_LARGE.length);
            response.getOutputStream().write(BODY_TOO_LARGE);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean isHttpTunnelRequest(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return path.startsWith("/http/");
    }
}
