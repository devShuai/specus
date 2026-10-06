package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.httpshare.HttpShareRules;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.HttpShareService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * JSON answers of the temporary-share endpoints. Bodies are written here rather than by the MVC
 * converters so that every answer has the exact contract shape: {@code {"code": ...}} for errors,
 * explicit {@code null} fields, and the cache headers the contract requires.
 */
final class HttpShareResponses {
    private static final ObjectMapper JSON = new ObjectMapper();

    private HttpShareResponses() {
    }

    /**
     * Runs a management operation for the authenticated caller. A token whose user is gone,
     * disabled or unbound is answered like any caller who cannot manage the route.
     */
    static ResponseEntity<byte[]> management(ManagementContextResolver resolver,
                                             Jwt jwt,
                                             int deniedStatus,
                                             String deniedCode,
                                             Function<ManagementContext, HttpShareService.ApiResult> operation) {
        ManagementContext context;
        try {
            context = resolver.resolve(jwt);
        } catch (ResponseStatusException denied) {
            if (denied.getStatusCode().value() == HttpStatus.UNAUTHORIZED.value()) {
                throw denied;
            }
            return error(deniedStatus, deniedCode, Map.of(), "private, no-store");
        }
        try {
            HttpShareService.ApiResult result = operation.apply(context);
            return json(result.status(), result.body(), result.headers(), "private, no-store");
        } catch (HttpShareService.ShareProblem problem) {
            return error(problem.status(), problem.code(), problem.headers(), "private, no-store");
        }
    }

    static ResponseEntity<byte[]> json(int status, Object body, Map<String, String> headers, String cacheControl) {
        byte[] bytes;
        try {
            bytes = JSON.writeValueAsBytes(body);
        } catch (JsonProcessingException e) {
            return error(503, HttpShareRules.CODE_UNAVAILABLE, Map.of(), cacheControl);
        }
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.CACHE_CONTROL, headers.getOrDefault(HttpHeaders.CACHE_CONTROL, cacheControl));
        headers.forEach((name, value) -> {
            if (!HttpHeaders.CACHE_CONTROL.equalsIgnoreCase(name)) {
                builder.header(name, value);
            }
        });
        return builder.body(bytes);
    }

    static ResponseEntity<byte[]> error(int status, String code, Map<String, String> headers, String cacheControl) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", code);
        return json(status, body, headers, cacheControl);
    }
}
