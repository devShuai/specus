package com.theshuai.tunnelserver.management.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Component
public class ManagementAuthFilter extends OncePerRequestFilter {
    private final String expectedAuthorization;

    public ManagementAuthFilter(@Value("${tunnel.management.username:admin}") String username,
                                @Value("${tunnel.management.password:admin}") String password) {
        expectedAuthorization = "Basic " + Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && MessageDigest.isEqual(
                authorization.getBytes(StandardCharsets.UTF_8),
                expectedAuthorization.getBytes(StandardCharsets.UTF_8))) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setHeader("WWW-Authenticate", "Basic realm=\"shuai-tunnel\"");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
