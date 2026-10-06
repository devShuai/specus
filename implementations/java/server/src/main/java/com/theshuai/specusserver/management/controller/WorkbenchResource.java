package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.WorkbenchClock;
import com.theshuai.specusserver.management.service.WorkbenchRateLimiter;
import com.theshuai.specusserver.management.service.WorkbenchService;
import com.theshuai.specusserver.management.service.WorkbenchService.Document;
import com.theshuai.specusserver.management.service.WorkbenchService.Reference;
import jakarta.persistence.PersistenceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.TransactionException;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * {@code /api/admin/workbench}: the caller's own favourite services and recent opens
 * (protocol/spec/service-workbench.md section 5). There is no query parameter and no request body
 * is read; no path, query or body field names an identity, so nobody -- administrators included --
 * reads or clears another identity's lists.
 *
 * <p>Order of refusals: the shared authentication layer (401, or 403 for a token whose account is
 * gone or disabled); 400 {@code WORKBENCH_REQUEST_INVALID} for a {@code kind}/{@code id} outside the
 * contract; for growth only, 429 {@code WORKBENCH_RATE_LIMITED}; 503 {@code WORKBENCH_UNAVAILABLE}
 * when the store fails at any step; for growth only, 404 {@code WORKBENCH_TARGET_NOT_FOUND}; for an
 * add only, 409 {@code WORKBENCH_FAVORITES_FULL}. Success is 200 with the full document, writes
 * included. Every response carries {@code Cache-Control: private, no-store}.
 *
 * <p>Successful requests are never logged; a 503 logs tenant, user and operation, never the
 * reference.
 */
@RestController
@RequestMapping("/api/admin/workbench")
@Slf4j
public class WorkbenchResource {
    static final String CACHE_CONTROL = "private, no-store";
    /** Writes of one identity are serialised on this instance (the favourite bound, one row per reference). */
    private static final int IDENTITY_LOCK_STRIPES = 64;

    private final ManagementContextResolver contextResolver;
    private final WorkbenchService service;
    private final WorkbenchRateLimiter rateLimiter;
    private final WorkbenchClock clock;
    private final Object[] identityLocks = new Object[IDENTITY_LOCK_STRIPES];

    public WorkbenchResource(ManagementContextResolver contextResolver,
                             WorkbenchService service,
                             WorkbenchRateLimiter rateLimiter,
                             WorkbenchClock clock) {
        this.contextResolver = contextResolver;
        this.service = service;
        this.rateLimiter = rateLimiter;
        this.clock = clock;
        for (int i = 0; i < identityLocks.length; i++) {
            identityLocks[i] = new Object();
        }
    }

    @GetMapping
    public ResponseEntity<Object> read(@AuthenticationPrincipal Jwt jwt) {
        ManagementContext context = contextResolver.resolve(jwt);
        return run(context, "get", false, () -> service.read(context, clock.millis()));
    }

    @PutMapping("/favorites/{kind}/{id}")
    public ResponseEntity<Object> addFavorite(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable("kind") String kind,
                                              @PathVariable("id") String id) {
        ManagementContext context = contextResolver.resolve(jwt);
        Reference reference = WorkbenchService.parseReference(kind, id);
        if (reference == null) {
            return invalidRequest();
        }
        long now = clock.millis();
        ResponseEntity<Object> limited = rateLimited(context, now);
        if (limited != null) {
            return limited;
        }
        return run(context, "add-favorite", true, () -> service.addFavorite(context, reference, now));
    }

    @DeleteMapping("/favorites/{kind}/{id}")
    public ResponseEntity<Object> removeFavorite(@AuthenticationPrincipal Jwt jwt,
                                                 @PathVariable("kind") String kind,
                                                 @PathVariable("id") String id) {
        ManagementContext context = contextResolver.resolve(jwt);
        Reference reference = WorkbenchService.parseReference(kind, id);
        if (reference == null) {
            return invalidRequest();
        }
        return run(context, "remove-favorite", true,
                () -> service.removeFavorite(context, reference, clock.millis()));
    }

    @DeleteMapping("/favorites")
    public ResponseEntity<Object> clearFavorites(@AuthenticationPrincipal Jwt jwt) {
        ManagementContext context = contextResolver.resolve(jwt);
        return run(context, "clear-favorites", true, () -> service.clearFavorites(context, clock.millis()));
    }

    @PostMapping("/recents/{kind}/{id}")
    public ResponseEntity<Object> recordVisit(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable("kind") String kind,
                                              @PathVariable("id") String id) {
        ManagementContext context = contextResolver.resolve(jwt);
        Reference reference = WorkbenchService.parseReference(kind, id);
        if (reference == null) {
            return invalidRequest();
        }
        long now = clock.millis();
        ResponseEntity<Object> limited = rateLimited(context, now);
        if (limited != null) {
            return limited;
        }
        return run(context, "record-visit", true, () -> service.recordVisit(context, reference, now));
    }

    @DeleteMapping("/recents/{kind}/{id}")
    public ResponseEntity<Object> removeRecent(@AuthenticationPrincipal Jwt jwt,
                                               @PathVariable("kind") String kind,
                                               @PathVariable("id") String id) {
        ManagementContext context = contextResolver.resolve(jwt);
        Reference reference = WorkbenchService.parseReference(kind, id);
        if (reference == null) {
            return invalidRequest();
        }
        return run(context, "remove-recent", true,
                () -> service.removeRecent(context, reference, clock.millis()));
    }

    @DeleteMapping("/recents")
    public ResponseEntity<Object> clearRecents(@AuthenticationPrincipal Jwt jwt) {
        ManagementContext context = contextResolver.resolve(jwt);
        return run(context, "clear-recents", true, () -> service.clearRecents(context, clock.millis()));
    }

    /** The shared authentication layer's refusal (401/403), with this resource's cache policy. */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, String>> handleResponseStatus(ResponseStatusException exception) {
        String message = StringUtils.hasText(exception.getReason()) ? exception.getReason() : "请求失败";
        return ResponseEntity.status(exception.getStatusCode())
                .header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL)
                .body(Map.of("error", message));
    }

    private ResponseEntity<Object> rateLimited(ManagementContext context, long now) {
        long retryAfterSeconds = rateLimiter.acquire(context.tenant().tenantId(), context.username(), now);
        if (retryAfterSeconds <= 0) {
            return null;
        }
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL)
                .header(HttpHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds))
                .body(errorBody("WORKBENCH_RATE_LIMITED", "too many workbench writes, retry later"));
    }

    private ResponseEntity<Object> run(ManagementContext context, String op, boolean write, Supplier<Document> action) {
        try {
            Document document;
            if (write) {
                synchronized (identityLock(context)) {
                    document = action.get();
                }
            } else {
                document = action.get();
            }
            return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL).body(document);
        } catch (WorkbenchService.Refusal refusal) {
            return error(refusal.status(), refusal.code(), refusal.getMessage());
        } catch (DataAccessException | TransactionException | PersistenceException storage) {
            // A store that cannot be read is never reported as empty lists.
            log.warn("[workbench] tenant={} user={} op={} code=WORKBENCH_UNAVAILABLE",
                    context.tenant().tenantId(), context.username(), op);
            return error(HttpStatus.SERVICE_UNAVAILABLE, "WORKBENCH_UNAVAILABLE", "workbench storage is unavailable");
        }
    }

    private Object identityLock(ManagementContext context) {
        String identity = context.tenant().tenantId() + "\n" + context.username();
        return identityLocks[Math.floorMod(identity.hashCode(), identityLocks.length)];
    }

    private static ResponseEntity<Object> invalidRequest() {
        return error(HttpStatus.BAD_REQUEST, "WORKBENCH_REQUEST_INVALID",
                "kind must be http-route, tcp-mapping or peer-service and id an integer 1..2^53-1");
    }

    private static ResponseEntity<Object> error(HttpStatusCode status, String code, String message) {
        return ResponseEntity.status(status)
                .header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL)
                .body(errorBody(code, message));
    }

    private static Map<String, String> errorBody(String code, String message) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("code", code);
        body.put("error", message);
        return body;
    }
}
