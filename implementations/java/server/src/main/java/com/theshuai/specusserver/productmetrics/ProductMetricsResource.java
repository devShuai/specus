package com.theshuai.specusserver.productmetrics;

import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.productmetrics.ProductMetricsService.Response;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * {@code /api/admin/product-metrics} (protocol/spec/product-metrics.md section 7). The shared Bearer
 * authentication applies; the tenant and the username come from the session only. Bodies are read
 * raw (at most one byte past the limit), never bound to a type that could ignore an unknown field,
 * and never logged. Every answer carries {@code Cache-Control: private, no-store}.
 */
@RestController
@RequestMapping("/api/admin/product-metrics")
public class ProductMetricsResource {
    static final String CACHE_CONTROL = "private, no-store";

    private final ManagementContextResolver contextResolver;
    private final ProductMetricsService service;

    public ProductMetricsResource(ManagementContextResolver contextResolver, ProductMetricsService service) {
        this.contextResolver = contextResolver;
        this.service = service;
    }

    @GetMapping("/settings")
    public ResponseEntity<Object> settings(@AuthenticationPrincipal Jwt jwt) {
        return answer(service.settings(contextResolver.resolve(jwt)));
    }

    @PutMapping("/settings")
    public ResponseEntity<Object> putSettings(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request)
            throws IOException {
        ManagementContext context = contextResolver.resolve(jwt);
        if (!context.isAdmin()) {
            return answer(new Response(403, null));
        }
        byte[] body = readLimited(request.getInputStream());
        if (body.length > ProductMetricsModel.MAX_BODY_BYTES) {
            return answer(Response.code(400, ProductMetricsModel.CODE_INVALID));
        }
        return answer(service.putSettings(context, body));
    }

    @DeleteMapping("/data")
    public ResponseEntity<Object> purge(@AuthenticationPrincipal Jwt jwt) {
        return answer(service.purge(contextResolver.resolve(jwt)));
    }

    @PostMapping("/transfer-outcomes")
    public ResponseEntity<Object> ingest(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request)
            throws IOException {
        ManagementContext context = contextResolver.resolve(jwt);
        return answer(service.ingest(context, readLimited(request.getInputStream())));
    }

    @GetMapping("/summary")
    public ResponseEntity<Object> summary(@AuthenticationPrincipal Jwt jwt,
                                          @RequestParam Map<String, String> query) {
        return answer(service.summary(contextResolver.resolve(jwt), query));
    }

    /** The shared authentication layer's refusal (401/403), with this resource's cache policy. */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, String>> handleResponseStatus(ResponseStatusException exception) {
        String message = StringUtils.hasText(exception.getReason()) ? exception.getReason() : "请求失败";
        return ResponseEntity.status(exception.getStatusCode())
                .header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL)
                .body(Map.of("error", message));
    }

    private static ResponseEntity<Object> answer(Response response) {
        Object body = response.body();
        if (response.status() == 403 && body == null) {
            body = Map.of("error", "需要 admin 权限");
        }
        return ResponseEntity.status(response.status())
                .header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    /** Reads at most MAX_BODY_BYTES + 1 bytes: enough to tell an oversized body without reading it. */
    private static byte[] readLimited(InputStream input) throws IOException {
        return input.readNBytes(ProductMetricsModel.MAX_BODY_BYTES + 1);
    }
}
