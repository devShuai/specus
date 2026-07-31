package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.config.OidcProperties;
import com.theshuai.specusserver.management.service.RegistrationService;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.ManagementUserService.LoginUser;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.security.TurnstileVerifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Public OIDC helper endpoints for the single-page admin UI:
 * <ul>
 *   <li>{@code GET /oidc-config} — the parameters the browser needs to start Authorization Code + PKCE.</li>
 *   <li>{@code POST /oidc/token} — a same-origin proxy that exchanges the authorization code for tokens,
 *       so the SPA never has to call the gateway's token endpoint directly (avoids CORS and keeps the
 *       optional client secret on the server).</li>
 * </ul>
 */
@RestController
@Slf4j
public class OidcController {
    private final OidcProperties properties;
    private final LocalTokenService localTokenService;
    private final ManagementUserService managementUserService;
    private final RegistrationService registrationService;
    private final TurnstileVerifier turnstileVerifier;
    private final ObjectProvider<JwtDecoder> jwtDecoderProvider;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public OidcController(OidcProperties properties,
                          LocalTokenService localTokenService,
                          ManagementUserService managementUserService,
                          RegistrationService registrationService,
                          TurnstileVerifier turnstileVerifier,
                          ObjectProvider<JwtDecoder> jwtDecoderProvider) {
        this.properties = properties;
        this.localTokenService = localTokenService;
        this.managementUserService = managementUserService;
        this.registrationService = registrationService;
        this.turnstileVerifier = turnstileVerifier;
        this.jwtDecoderProvider = jwtDecoderProvider;
    }

    @GetMapping("/oidc-config")
    public Map<String, Object> config() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("configured", StringUtils.hasText(properties.getClientId()));
        config.put("authorizationEndpoint", properties.getAuthorizationEndpoint());
        config.put("endSessionEndpoint", properties.getEndSessionEndpoint());
        config.put("clientId", properties.getClientId());
        config.put("redirectUri", properties.getRedirectUri());
        config.put("scope", properties.getScope());
        config.put("passwordLoginEnabled", localTokenService.isPasswordLoginEnabled());
        config.put("registrationEnabled", registrationService.isAvailable());
        config.put("emailVerificationRequired", registrationService.isAvailable());
        boolean turnstileAvailable = turnstileVerifier.isEnabled() && turnstileVerifier.isConfigured();
        config.put("turnstileEnabled", turnstileAvailable);
        config.put("turnstileSiteKey", turnstileAvailable ? turnstileVerifier.getSiteKey() : "");
        return config;
    }

    @PostMapping("/oidc/token")
    public ResponseEntity<?> exchange(@RequestBody TokenExchangeRequest request) {
        if (!StringUtils.hasText(properties.getClientId())) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "OIDC 未配置（缺少 client-id）"));
        }
        if (request == null
                || !StringUtils.hasText(request.code())
                || !StringUtils.hasText(request.codeVerifier())
                || !StringUtils.hasText(request.nonce())) {
            return ResponseEntity.badRequest().body(Map.of("error", "缺少 code、code_verifier 或 nonce"));
        }

        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", request.code());
        form.put("redirect_uri", properties.getRedirectUri());
        form.put("code_verifier", request.codeVerifier());
        // Public PKCE client: client_id in the body. Confidential client: HTTP Basic below.
        if (!StringUtils.hasText(properties.getClientSecret())) {
            form.put("client_id", properties.getClientId());
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(properties.getTokenEndpoint()))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)));
        if (StringUtils.hasText(properties.getClientSecret())) {
            String basic = Base64.getEncoder().encodeToString(
                    (properties.getClientId() + ":" + properties.getClientSecret()).getBytes(StandardCharsets.UTF_8));
            builder.header("Authorization", "Basic " + basic);
        }

        try {
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            JsonNode body = JsonUtil.readString(response.body());
            if (body == null) {
                log.warn("[oidc] token exchange returned unparseable body, status={}", response.statusCode());
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of("error", "OIDC 令牌响应无法解析"));
            }
            if (response.statusCode() / 100 != 2) {
                log.warn("[oidc] token exchange failed status={} error={}", response.statusCode(), body.path("error").asText(""));
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of(
                        "error", body.path("error").asText("token_exchange_failed"),
                        "error_description", body.path("error_description").asText("")));
            }
            String rawIdToken = body.path("id_token").asText("");
            if (!StringUtils.hasText(rawIdToken)) {
                log.warn("[oidc] token exchange response is missing id_token");
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                        .body(Map.of("error", "OIDC 响应缺少 ID Token"));
            }
            Jwt idToken;
            try {
                JwtDecoder jwtDecoder = jwtDecoderProvider.getIfAvailable();
                if (jwtDecoder == null) {
                    log.warn("[oidc] JWT decoder is unavailable");
                    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                            .body(Map.of("error", "OIDC 校验服务不可用"));
                }
                idToken = jwtDecoder.decode(rawIdToken);
            } catch (JwtException e) {
                log.warn("[oidc] ID Token validation failed: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                        .body(Map.of("error", "OIDC ID Token 校验失败"));
            }
            if (!StringUtils.hasText(idToken.getSubject())
                    || !constantTimeEquals(request.nonce(), claimAsString(idToken, "nonce"))) {
                log.warn("[oidc] ID Token subject or nonce validation failed");
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                        .body(Map.of("error", "OIDC ID Token 身份或 nonce 校验失败"));
            }
            String preferredUsername = claimAsString(idToken, "preferred_username");
            Optional<LoginUser> loginUser = managementUserService.resolveOidcUser(preferredUsername);
            if (loginUser.isEmpty()) {
                log.warn("[oidc] authenticated Certus identity is not provisioned in Specus");
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "该 Certus 账号尚未获准访问 Specus"));
            }
            LoginUser user = loginUser.get();
            Map<String, Object> tokens = new LinkedHashMap<>();
            tokens.put("accessToken",
                    localTokenService.issueToken(user.username(), user.tenantId(), user.role()));
            // Kept in sessionStorage by the browser and used only as an RP-Initiated Logout hint.
            tokens.put("idToken", rawIdToken);
            tokens.put("tokenType", body.path("token_type").asText("Bearer"));
            tokens.put("expiresIn", localTokenService.getTtlSeconds());
            return ResponseEntity.ok(tokens);
        } catch (Exception e) {
            log.warn("[oidc] token exchange error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of("error", "无法连接 OIDC 令牌端点"));
        }
    }

    private static String formEncode(Map<String, String> form) {
        StringBuilder builder = new StringBuilder();
        form.forEach((key, value) -> {
            if (!builder.isEmpty()) {
                builder.append('&');
            }
            builder.append(URLEncoder.encode(key, StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        });
        return builder.toString();
    }

    private static String claimAsString(Jwt jwt, String claimName) {
        Object value = jwt.getClaims().get(claimName);
        return value == null ? "" : value.toString();
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    public record TokenExchangeRequest(String code, String codeVerifier, String nonce) {
    }
}
