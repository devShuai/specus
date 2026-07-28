package com.theshuai.specusserver.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.config.TurnstileProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
public class TurnstileVerifier {
    public static final String LOGIN_ACTION = "login";
    public static final String REGISTER_ACTION = "register";

    private final TurnstileProperties properties;
    private final HttpClient httpClient;

    @Autowired
    public TurnstileVerifier(TurnstileProperties properties) {
        this(properties, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build());
    }

    TurnstileVerifier(TurnstileProperties properties, HttpClient httpClient) {
        this.properties = properties;
        this.httpClient = httpClient;
    }

    public boolean isEnabled() {
        return properties.isEnabled();
    }

    public boolean isConfigured() {
        return !properties.isEnabled()
                || (StringUtils.hasText(properties.getSiteKey())
                && StringUtils.hasText(properties.getSecretKey())
                && StringUtils.hasText(properties.getVerifyUrl())
                && properties.getAllowedHostnames().stream().anyMatch(StringUtils::hasText));
    }

    public String getSiteKey() {
        return properties.getSiteKey();
    }

    public void verify(String responseToken, String expectedAction) {
        if (!properties.isEnabled()) {
            return;
        }
        if (!isConfigured()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Turnstile 未正确配置");
        }
        if (!StringUtils.hasText(responseToken)) {
            throw rejected();
        }

        String body = "secret=" + encode(properties.getSecretKey())
                + "&response=" + encode(responseToken.trim());
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder(URI.create(properties.getVerifyUrl()))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Turnstile 验证地址无效");
        }

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                log.warn("[turnstile] siteverify returned HTTP {}", response.statusCode());
                throw unavailable();
            }
            JsonNode result = JsonUtil.readString(response.body());
            if (result == null) {
                throw unavailable();
            }
            String actualAction = result.path("action").asText("");
            String hostname = normalizeHostname(result.path("hostname").asText(""));
            boolean accepted = result.path("success").asBoolean(false)
                    && expectedAction.equals(actualAction)
                    && hostnameAllowed(hostname);
            if (!accepted) {
                log.info("[turnstile] rejected action={} actualAction={} hostname={} errors={}",
                        expectedAction, actualAction, hostname, result.path("error-codes"));
                throw rejected();
            }
        } catch (ResponseStatusException exception) {
            throw exception;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw unavailable();
        } catch (Exception exception) {
            log.warn("[turnstile] verification failed: {}", exception.getMessage());
            throw unavailable();
        }
    }

    private boolean hostnameAllowed(String hostname) {
        Set<String> allowed = properties.getAllowedHostnames().stream()
                .map(TurnstileVerifier::normalizeHostname)
                .filter(StringUtils::hasText)
                .collect(Collectors.toSet());
        return allowed.contains(hostname);
    }

    private static String normalizeHostname(String hostname) {
        return hostname == null ? "" : hostname.trim().toLowerCase(Locale.ROOT).replaceFirst("\\.$", "");
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static ResponseStatusException rejected() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "人机验证失败，请重试");
    }

    private static ResponseStatusException unavailable() {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "人机验证服务暂不可用");
    }
}
