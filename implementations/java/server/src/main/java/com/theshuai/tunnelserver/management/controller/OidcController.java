package com.theshuai.tunnelserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelserver.config.OidcProperties;
import com.theshuai.tunnelserver.management.service.RegistrationService;
import com.theshuai.tunnelserver.security.LocalTokenService;
import com.theshuai.tunnelserver.security.TurnstileVerifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

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
    private final RegistrationService registrationService;
    private final TurnstileVerifier turnstileVerifier;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public OidcController(OidcProperties properties, LocalTokenService localTokenService,
                          RegistrationService registrationService,
                          TurnstileVerifier turnstileVerifier) {
        this.properties = properties;
        this.localTokenService = localTokenService;
        this.registrationService = registrationService;
        this.turnstileVerifier = turnstileVerifier;
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
        if (request == null || !StringUtils.hasText(request.code()) || !StringUtils.hasText(request.codeVerifier())) {
            return ResponseEntity.badRequest().body(Map.of("error", "缺少 code 或 code_verifier"));
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
            Map<String, Object> tokens = new LinkedHashMap<>();
            tokens.put("accessToken", body.path("access_token").asText(null));
            tokens.put("idToken", body.path("id_token").asText(null));
            tokens.put("tokenType", body.path("token_type").asText("Bearer"));
            tokens.put("expiresIn", body.path("expires_in").asLong(0));
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

    public record TokenExchangeRequest(String code, String codeVerifier) {
    }
}
