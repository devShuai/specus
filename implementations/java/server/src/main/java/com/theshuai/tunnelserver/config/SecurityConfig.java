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
 * Locks down the management API and public OSS transfer endpoints with bearer JWTs, while leaving
 * the static page, OIDC helpers, Direct/TURN discovery and public {@code /http/**} tunnel ingress
 * open. Two token kinds are routed by the JWT {@code alg} header: RS256 from the OIDC gateway
 * (verified via JWKS) and HS256 minted by local username/password login. Only applies in a servlet
 * web context.
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtDecoder jwtDecoder,
                                                   ObjectStorageProperties objectStorageProperties) throws Exception {
        // 启用对象存储(OSS 兜底上传/下载)时,浏览器需直连 bucket 域名 PUT/GET 与内联预览,
        // 未放行会被 connect-src/img-src/media-src 拦死,直连失败后的兜底链路整体不可用。
        // provider=disabled(默认)时后缀为空,CSP 与原先字节一致,不影响既有部署。
        String ossOrigin = ossCspOrigin(objectStorageProperties);
        String ossSuffix = ossOrigin.isEmpty() ? "" : " " + ossOrigin;
        http
                .authorizeHttpRequests(authorize -> authorize
                        // /ws/** 由 JwtHandshakeInterceptor 在握手阶段单独鉴权，
                        // 这里放行避免被 Spring Security 当 REST 一样要求 Authorization 头（浏览器
                        // 原生 WebSocket 无法塞自定义 header，token 走 query 串）。
                        .requestMatchers("/ws/**").permitAll()
                        // 对象存储会产生持久化与公网流量成本，公开互传页只有登录用户
                        // 可以申请 OSS 上传/下载；房间发现、ICE 和实时 Direct/TURN 仍免登录。
                        .requestMatchers("/api/public/transfer/attachments/**").authenticated()
                        // 其余公开 API 无需 JWT，登录页和未登录用户也能读取。
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
                 *     额外放行 GA 初始化的内联脚本 sha256 hash（同时保留在 /gtag-init.js 作 fallback）；
                 *     该内联 config 显式使用无 query/hash 的 page_location 与 page_path，避免上报房间凭据。
                 *     如果修改 index.html 中的内联 gtag 片段，需要重算 sha256 并同步这里。
                 * - style-src 'self' 'unsafe-inline':HeroUI/framer-motion 会写内联 style 属性
                 * - img-src 允许 blob:/data: 供直连文件预览与内联图片;额外允许 GA pixel beacon 域
                 * - media-src 允许 blob:/data: 供直连视频/音频预览
                 * - object-src / frame-src 允许 blob: 供 PDF 预览
                 * - font-src 允许 data:
                 * - connect-src 允许 ws:/wss: 供 /ws/connections,以及 GA4 /g/collect 上报域
                 * - form-action 'self' 阻止跨站表单提交;frame-ancestors 'none' 防 clickjacking
                 *
                 * 同时加 Referrer-Policy: strict-origin-when-cross-origin（同源带完整 referrer
                 * 让 GA 能识别站内跳转，跨域只发 origin 不泄露路径）与 X-Frame-Options: DENY。
                 */
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; "
                                + "script-src 'self' https://www.googletagmanager.com 'sha256-sTRDNOsQlwtkSpNEy6tDUxqi0/WSUG1VrhzE550hzwo='; "
                                + "style-src 'self' 'unsafe-inline'; "
                                + "img-src 'self' blob: data: https://www.google-analytics.com https://*.googletagmanager.com" + ossSuffix + "; "
                                + "media-src 'self' blob: data:" + ossSuffix + "; "
                                + "object-src 'self' blob:; "
                                + "frame-src 'self' blob:; "
                                + "font-src 'self' data:; "
                                + "connect-src 'self' ws: wss: https://www.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com" + ossSuffix + "; "
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
        return path.startsWith("/api/admin/")
                || path.startsWith("/api/public/transfer/attachments/")
                || "/auth/refresh".equals(path);
    }

    /**
     * 计算对象存储 bucket 的 CSP 来源(如 {@code https://my-bucket.oss-cn-hangzhou.aliyuncs.com})。
     * 仅在 {@code provider=aliyun-oss} 且 endpoint / bucket 均已配置时返回,否则返回空串,CSP 保持不变。
     * bucket 域名 = {@code <bucket>.<endpoint host>},与 AliyunOssObjectStorageService.objectUrl 一致。
     */
    private String ossCspOrigin(ObjectStorageProperties props) {
        if (props == null || !"aliyun-oss".equalsIgnoreCase(props.getProvider())) {
            return "";
        }
        String endpoint = props.getEndpoint() == null ? "" : props.getEndpoint().trim();
        String bucket = props.getBucket() == null ? "" : props.getBucket().trim();
        if (endpoint.isEmpty() || bucket.isEmpty()) {
            return "";
        }
        String host = endpoint.replaceFirst("(?i)^https?://", "").replaceAll("/.*$", "").trim();
        if (host.isEmpty()) {
            return "";
        }
        return "https://" + bucket + "." + host;
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
