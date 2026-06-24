package com.theshuai.tunnelserver.config;

import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelserver.security.LocalTokenService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Locks down the management API with bearer JWTs and leaves everything else open (static page, OIDC
 * and auth helper endpoints, the public {@code /http/**} tunnel ingress). The admin API accepts two
 * token kinds, routed by the JWT {@code alg} header: RS256 from the OIDC gateway (verified via
 * JWKS) and HS256 minted by local username/password login. Only applies in a servlet web context.
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // /ws/** 由 JwtHandshakeInterceptor 在握手阶段单独鉴权，
                        // 这里放行避免被 Spring Security 当 REST 一样要求 Authorization 头（浏览器
                        // 原生 WebSocket 无法塞自定义 header，token 走 query 串）。
                        .requestMatchers("/ws/**").permitAll()
                        // 公开 API：无需 JWT，登录页和未登录用户也能读取。当前用于
                        // 客户端下载链接展示（GET /api/public/client-downloads）。
                        .requestMatchers("/api/public/**").permitAll()
                        .requestMatchers("/api/admin/**", "/auth/refresh").authenticated()
                        .anyRequest().permitAll())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenResolver(adminApiBearerTokenResolver())
                        .jwt(jwt -> jwt.decoder(jwtDecoder)))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                /*
                 * CSP：管理后台为 React + HeroUI 构建产物,脚本是同源外部 bundle(/assets/*.js)。
                 * - script-src 'self' + googletagmanager.com:外部模块脚本同源 + GA 主 loader
                 * - style-src 'self' 'unsafe-inline':HeroUI/framer-motion 会写内联 style 属性
                 * - img-src / font-src 允许 data:;额外允许 GA pixel beacon 域
                 * - connect-src 允许 ws:/wss: 供 /ws/connections,以及 GA4 /g/collect 上报域
                 * - form-action 'self' 阻止跨站表单提交;frame-ancestors 'none' 防 clickjacking
                 *
                 * 同时加 Referrer-Policy: strict-origin-when-cross-origin（同源带完整 referrer
                 * 让 GA 能识别站内跳转，跨域只发 origin 不泄露路径）与 X-Frame-Options: DENY。
                 */
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; "
                                + "script-src 'self' https://www.googletagmanager.com; "
                                + "style-src 'self' 'unsafe-inline'; "
                                + "img-src 'self' data: https://www.google-analytics.com https://*.googletagmanager.com; "
                                + "font-src 'self' data:; "
                                + "connect-src 'self' ws: wss: https://www.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com; "
                                + "form-action 'self'; "
                                + "frame-ancestors 'none'; "
                                + "base-uri 'self'"))
                        .referrerPolicy(rp -> rp.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        .frameOptions(frame -> frame.deny()));
        return http.build();
    }

    private BearerTokenResolver adminApiBearerTokenResolver() {
        DefaultBearerTokenResolver delegate = new DefaultBearerTokenResolver();
        return request -> shouldAuthenticateBearer(request) ? delegate.resolve(request) : null;
    }

    private boolean shouldAuthenticateBearer(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return path.startsWith("/api/admin/") || "/auth/refresh".equals(path);
    }

    @Bean
    public JwtDecoder jwtDecoder(OidcProperties oidc, LocalTokenService localTokenService) {
        return new AlgorithmRoutingJwtDecoder(oidcDecoder(oidc), localDecoder(localTokenService));
    }

    /** Lazy JWKS-backed decoder for the gateway's RS256 tokens (keys fetched on first use). */
    private JwtDecoder oidcDecoder(OidcProperties oidc) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(oidc.getJwkSetUri()).build();
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        if (StringUtils.hasText(oidc.getIssuer())) {
            validators.add(new JwtIssuerValidator(oidc.getIssuer()));
        }
        if (StringUtils.hasText(oidc.getAudience())) {
            validators.add(audienceValidator(oidc.getAudience()));
        }
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    /** HS256 decoder for the locally-minted password-login tokens. */
    private JwtDecoder localDecoder(LocalTokenService localTokenService) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(localTokenService.getSecretKey())
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                new JwtIssuerValidator(LocalTokenService.ISSUER)));
        return decoder;
    }

    private OAuth2TokenValidator<Jwt> audienceValidator(String audience) {
        OAuth2Error error = new OAuth2Error("invalid_token", "Required audience " + audience + " is missing", null);
        return jwt -> jwt.getAudience() != null && jwt.getAudience().contains(audience)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(error);
    }

    /** Picks the decoder by the JWT header {@code alg}: HS* → local, otherwise → OIDC/JWKS. */
    private static final class AlgorithmRoutingJwtDecoder implements JwtDecoder {
        private final JwtDecoder oidcDecoder;
        private final JwtDecoder localDecoder;

        private AlgorithmRoutingJwtDecoder(JwtDecoder oidcDecoder, JwtDecoder localDecoder) {
            this.oidcDecoder = oidcDecoder;
            this.localDecoder = localDecoder;
        }

        @Override
        public Jwt decode(String token) throws JwtException {
            return isHmac(token) ? localDecoder.decode(token) : oidcDecoder.decode(token);
        }

        private boolean isHmac(String token) {
            int dot = token == null ? -1 : token.indexOf('.');
            if (dot <= 0) {
                return false;
            }
            try {
                byte[] header = Base64.getUrlDecoder().decode(token.substring(0, dot));
                JsonNode node = JsonUtil.readString(new String(header, java.nio.charset.StandardCharsets.UTF_8));
                String alg = node == null ? "" : node.path("alg").asText("");
                return alg.startsWith("HS");
            } catch (RuntimeException e) {
                return false;
            }
        }
    }
}
