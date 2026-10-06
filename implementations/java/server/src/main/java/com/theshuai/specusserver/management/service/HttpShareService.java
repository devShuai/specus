package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.httpshare.GcraRateLimiter;
import com.theshuai.specusserver.httpshare.HttpShareRules;
import com.theshuai.specusserver.httpshare.HttpShareRules.Credentials;
import com.theshuai.specusserver.httpshare.HttpShareRuntime;
import com.theshuai.specusserver.httpshare.HttpShareStreamRegistry;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpAccessAudit;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.HttpShare;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpAccessAuditRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.HttpShareRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Temporary HTTP shares (protocol/spec/temporary-http-share.md): the management API, the
 * fragment-to-cookie exchange, the decision for every visitor request under {@code /http-share/},
 * the hooks that end shares when their route, client or creator changes, the sweep, and the
 * recheck that cuts in-flight streams.
 *
 * <p>The database is the only source of truth: every decision re-reads the share, its route, the
 * route's client and the creator. Nothing about authorization is cached, so a revocation on any
 * instance applies to the next request everywhere. Every revocation is a conditional update and
 * writes its audit entry in the same transaction only when it changed the row.
 */
@Service
@Slf4j
public class HttpShareService {
    /** Strict parser for request bodies: duplicate keys and trailing data are invalid. */
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final Set<String> CREATE_FIELDS = Set.of("expiresInSeconds", "access", "pathPrefix", "label");
    private static final int MAX_EXCHANGE_BODY_BYTES = 4096;
    private static final int DEFAULT_AUDIT_LIMIT = 50;
    private static final int MAX_AUDIT_LIMIT = 200;
    private static final long DAY_SECONDS = 86_400L;

    private final HttpShareRepository shares;
    private final HttpAccessAuditRepository audits;
    private final HttpRouteMappingRepository routes;
    private final ClientAccountRepository clients;
    private final ManagementUserRepository users;
    private final AuthProperties authProperties;
    private final HttpShareRuntime runtime;
    private final HttpShareStreamRegistry streams;
    private final TransactionTemplate transactions;
    private final boolean backgroundEnabled;
    private ScheduledExecutorService streamTicker;
    private long lastRecheckNanos = System.nanoTime();

    @PersistenceContext
    private EntityManager entityManager;

    public HttpShareService(HttpShareRepository shares,
                            HttpAccessAuditRepository audits,
                            HttpRouteMappingRepository routes,
                            ClientAccountRepository clients,
                            ManagementUserRepository users,
                            AuthProperties authProperties,
                            HttpShareRuntime runtime,
                            HttpShareStreamRegistry streams,
                            PlatformTransactionManager transactionManager,
                            @Value("${specus.http-share.background-enabled:true}") boolean backgroundEnabled) {
        this.shares = shares;
        this.audits = audits;
        this.routes = routes;
        this.clients = clients;
        this.users = users;
        this.authProperties = authProperties;
        this.runtime = runtime;
        this.streams = streams;
        this.transactions = new TransactionTemplate(transactionManager);
        this.backgroundEnabled = backgroundEnabled;
    }

    // =============================================================================================
    // Results

    /** A refusal of a share endpoint: the HTTP status, the {@code code} and extra headers. */
    public static final class ShareProblem extends RuntimeException {
        private final int status;
        private final String code;
        private final Map<String, String> headers;

        ShareProblem(int status, String code, Map<String, String> headers) {
            super(code, null, false, false);
            this.status = status;
            this.code = code;
            this.headers = headers == null ? Map.of() : headers;
        }

        public int status() {
            return status;
        }

        public String code() {
            return code;
        }

        public Map<String, String> headers() {
            return headers;
        }
    }

    /** A JSON answer of the management API or the exchange. */
    public record ApiResult(int status, Map<String, Object> body, Map<String, String> headers) {
    }

    /** What happens to one visitor request under {@code /http-share/}. */
    public sealed interface VisitorDecision permits Refusal, Admission {
    }

    /** Answered by the share path itself; {@code code} is null for the 308 redirect. */
    public record Refusal(int status, String code, Map<String, String> headers) implements VisitorDecision {
    }

    /**
     * The request is forwarded with the route's semantics. {@code stream} holds this request's
     * in-flight slot; the caller attaches the tear-down action and releases it when done.
     */
    public record Admission(String shareId,
                            String access,
                            long routeId,
                            String clientName,
                            String routeName,
                            String relativePath,
                            String targetBaseUrl,
                            boolean pathRewriteEnabled,
                            HttpShareStreamRegistry.InFlight stream) implements VisitorDecision {
    }

    private record Actor(String username, String tenantId, boolean admin) {
    }

    private record ShareWorld(HttpShare share, HttpRouteMapping route, ClientAccount client, Actor creator) {
    }

    private record CreateFields(int expiresInSeconds, String access, String pathPrefix, String label) {
    }

    private record ManagedRoute(HttpRouteMapping route, ClientAccount client, Actor actor) {
    }

    // =============================================================================================
    // Management API (spec section 4)

    public ApiResult create(ManagementContext context, String routeIdText, byte[] body) {
        CreateFields fields = validateCreate(body);
        Long routeId = parseId(routeIdText);
        return guarded(() -> transactions.execute(status -> {
            long now = runtime.nowSeconds();
            HttpRouteMapping route;
            ClientAccount client;
            Actor actor;
            long active;
            try {
                route = routeId == null ? null : routes.findById(routeId).orElse(null);
                client = route == null ? null : clients.findById(route.getClientId()).orElse(null);
                actor = lookupActor(context);
                active = route == null ? 0
                        : shares.countByRouteIdAndRevokedAtIsNullAndExpiresAtGreaterThan(route.getId(), now);
            } catch (RuntimeException readFailure) {
                throw unavailable(readFailure);
            }
            if (route == null || !canManage(actor, route, client)) {
                throw problem(404, HttpShareRules.CODE_ROUTE_NOT_FOUND);
            }
            if (!route.isEnabled()) {
                throw problem(409, HttpShareRules.CODE_ROUTE_DISABLED);
            }
            if (client == null || !client.isEnabled()) {
                throw problem(409, HttpShareRules.CODE_CLIENT_DISABLED);
            }
            if (!Boolean.TRUE.equals(route.getAuthEnabled())) {
                throw problem(409, HttpShareRules.CODE_ROUTE_PUBLIC);
            }
            if (active >= HttpShareRules.MAX_ACTIVE_PER_ROUTE) {
                throw problem(409, HttpShareRules.CODE_LIMIT_REACHED);
            }
            Credentials credentials = newUniqueCredentials();
            HttpShare share = new HttpShare();
            share.setShareId(credentials.shareId());
            share.setTenantId(tenantOf(route));
            share.setRouteId(route.getId());
            share.setTokenSha256(credentials.tokenSha256());
            share.setAccess(fields.access());
            share.setPathPrefix(fields.pathPrefix());
            share.setLabel(fields.label());
            share.setCreatedBy(actor.username());
            share.setCreatedAt(now);
            share.setExpiresAt(now + fields.expiresInSeconds());
            share.setExpiryRecorded(0);
            entityManager.persist(share);
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("access", share.getAccess());
            detail.put("pathPrefix", share.getPathPrefix());
            detail.put("expiresAt", stamp(share.getExpiresAt()));
            audit(share.getTenantId(), now, actor.username(), HttpShareRules.AUDIT_SHARE_CREATED,
                    share.getRouteId(), share.getShareId(), detail);
            entityManager.flush();
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("share", view(share, now));
            response.put("token", credentials.token());
            response.put("linkPath", credentials.linkPath());
            return new ApiResult(201, response, Map.of());
        }));
    }

    public ApiResult list(ManagementContext context, String routeIdText) {
        Long routeId = parseId(routeIdText);
        return guarded(() -> transactions.execute(status -> {
            long now = runtime.nowSeconds();
            ManagedRoute managed = requireManagedRoute(context, routeId);
            List<HttpShare> rows = read(() -> shares.findByRouteIdOrderByCreatedAtDescShareIdDesc(routeId));
            List<Map<String, Object>> views = new ArrayList<>();
            for (HttpShare share : rows) {
                views.add(view(revokeIfLapsed(share, managed, now), now));
            }
            return new ApiResult(200, Map.of("shares", views), Map.of());
        }));
    }

    public ApiResult get(ManagementContext context, String routeIdText, String shareId) {
        Long routeId = parseId(routeIdText);
        return guarded(() -> transactions.execute(status -> {
            long now = runtime.nowSeconds();
            ManagedRoute managed = requireManagedRoute(context, routeId);
            HttpShare share = revokeIfLapsed(requireShareOfRoute(managed, shareId), managed, now);
            return new ApiResult(200, Map.of("share", view(share, now)), Map.of());
        }));
    }

    /**
     * Revokes an active share for the caller. Idempotent: an already revoked or expired share is
     * answered with its current state and nothing is written. No lapse check runs first.
     */
    public ApiResult revoke(ManagementContext context, String routeIdText, String shareId, byte[] body) {
        if (!isEmptyObjectBody(body)) {
            throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
        }
        Long routeId = parseId(routeIdText);
        return guarded(() -> transactions.execute(status -> {
            long now = runtime.nowSeconds();
            ManagedRoute managed = requireManagedRoute(context, routeId);
            HttpShare share = requireShareOfRoute(managed, shareId);
            if (isActive(share, now)) {
                revokeShare(share, now, managed.actor().username(), HttpShareRules.REASON_REVOKED_BY_USER);
            }
            HttpShare current = reload(share);
            return new ApiResult(200, Map.of("share", view(current, now)), Map.of());
        }));
    }

    /** {@code GET /api/admin/http-routes/{routeId}/access-audit}: for whoever can manage the route. */
    public ApiResult routeAudit(ManagementContext context, String routeIdText, String limitText, String beforeText) {
        int limit = parseLimit(limitText);
        Long before = parseOptionalPositive(beforeText);
        Long routeId = parseId(routeIdText);
        return guarded(() -> transactions.execute(status -> {
            ManagedRoute managed = requireManagedRoute(context, routeId);
            return auditPage(tenantOf(managed.route()), routeId, before, limit);
        }));
    }

    /** {@code GET /api/admin/http-access-audit}: tenant administrators only; may name a deleted route. */
    public ApiResult tenantAudit(ManagementContext context, String routeIdText, String limitText, String beforeText) {
        int limit = parseLimit(limitText);
        Long before = parseOptionalPositive(beforeText);
        Long routeId = parseOptionalPositive(routeIdText);
        return guarded(() -> transactions.execute(status -> {
            Actor actor = read(() -> lookupActor(context));
            if (actor == null || !actor.admin()) {
                throw problem(403, HttpShareRules.CODE_FORBIDDEN);
            }
            return auditPage(actor.tenantId(), routeId, before, limit);
        }));
    }

    private ApiResult auditPage(String tenantId, Long routeId, Long before, int limit) {
        List<HttpAccessAudit> rows = read(() -> audits.findPage(tenantId, routeId, before, PageRequest.of(0, limit + 1)));
        boolean more = rows.size() > limit;
        List<Map<String, Object>> entries = new ArrayList<>();
        for (HttpAccessAudit row : rows.subList(0, Math.min(limit, rows.size()))) {
            entries.add(auditView(row));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("entries", entries);
        body.put("nextBefore", more ? entries.get(entries.size() - 1).get("auditId") : null);
        return new ApiResult(200, body, Map.of());
    }

    // =============================================================================================
    // Exchange (spec section 5.2)

    /**
     * Exchanges the token from the link fragment for the share cookie. {@code body} is null when
     * the request body exceeded the size limit.
     */
    public ApiResult exchange(String contentType, byte[] body, String sourceAddress) {
        if (!isJsonMediaType(contentType)) {
            throw problem(415, HttpShareRules.CODE_REQUEST_INVALID);
        }
        String token = exchangeToken(body);
        long waitMs = runtime.exchangeLimiter().tryAcquire(
                sourceAddress == null ? "unknown" : sourceAddress, runtime.nowMillis());
        if (waitMs > 0) {
            throw problem(429, HttpShareRules.CODE_RATE_LIMITED,
                    Map.of("Retry-After", Long.toString(GcraRateLimiter.retryAfterSeconds(waitMs))));
        }
        // From here on the attempt has been charged to the source address.
        String shareId = HttpShareRules.parseToken(token);
        if (shareId == null) {
            throw problem(404, HttpShareRules.CODE_NOT_FOUND);
        }
        long nowMs = runtime.nowMillis();
        long now = Math.floorDiv(nowMs, 1000L);
        ShareWorld world = loadWorldOrUnavailable(shareId);
        if (world == null || !HttpShareRules.tokenMatches(token, world.share().getTokenSha256())) {
            throw problem(404, HttpShareRules.CODE_NOT_FOUND);
        }
        String ended = endedCode(world, now);
        if (ended != null) {
            throw problem(410, ended);
        }
        HttpShare share = world.share();
        long maxAge = Math.max(1, Math.ceilDiv(share.getExpiresAt() * 1000L - nowMs, 1000L));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("shareId", shareId);
        response.put("location", HttpShareRules.SHARE_ROOT + shareId + share.getPathPrefix());
        response.put("expiresAt", stamp(share.getExpiresAt()));
        response.put("access", share.getAccess());
        response.put("pathPrefix", share.getPathPrefix());
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Set-Cookie", HttpShareRules.setCookie(shareId, token, maxAge));
        headers.put("Cache-Control", "no-store");
        headers.put("Referrer-Policy", "no-referrer");
        return new ApiResult(200, response, headers);
    }

    private String exchangeToken(byte[] body) {
        if (body == null || body.length > MAX_EXCHANGE_BODY_BYTES) {
            throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
        }
        JsonNode node = parseJson(body);
        if (node == null || !node.isObject() || node.size() != 1 || !node.has("token")
                || !node.get("token").isTextual()) {
            throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
        }
        return node.get("token").textValue();
    }

    // =============================================================================================
    // Visitor requests (spec section 6.1)

    /**
     * Decides one request under {@code /http-share/}, before its body is read, a NAT stream is
     * opened or a 101 is answered. {@code path} is the raw request path without the context path.
     */
    public VisitorDecision authorizeVisitor(String method,
                                            String path,
                                            String rawQuery,
                                            List<String> cookieHeaders,
                                            boolean upgrade) {
        String rest = path != null && path.startsWith(HttpShareRules.SHARE_ROOT)
                ? path.substring(HttpShareRules.SHARE_ROOT.length()) : "";
        int slash = rest.indexOf('/');
        String shareId = slash < 0 ? rest : rest.substring(0, slash);
        if (!HttpShareRules.isShareId(shareId)) {
            return refusal(404, HttpShareRules.CODE_NOT_FOUND);
        }
        if (slash < 0) {
            // The cookie path ends with a slash; without it the browser would not send the cookie.
            String location = HttpShareRules.SHARE_ROOT + shareId + "/"
                    + (StringUtils.hasLength(rawQuery) ? "?" + rawQuery : "");
            return new Refusal(308, null, Map.of("Location", location));
        }
        String relativePath = rest.substring(slash);
        ShareWorld world;
        try {
            world = loadWorldOrUnavailable(shareId);
        } catch (ShareProblem unavailable) {
            return refusal(unavailable.status(), unavailable.code());
        }
        if (world == null) {
            return refusal(404, HttpShareRules.CODE_NOT_FOUND);
        }
        HttpShare share = world.share();
        boolean proven = false;
        for (String candidate : HttpShareRules.credentialCandidates(cookieHeaders, shareId)) {
            if (HttpShareRules.tokenMatches(candidate, share.getTokenSha256())) {
                proven = true;
                break;
            }
        }
        if (!proven) {
            return refusal(404, HttpShareRules.CODE_NOT_FOUND);
        }
        long nowMs = runtime.nowMillis();
        String ended = endedCode(world, Math.floorDiv(nowMs, 1000L));
        if (ended != null) {
            return new Refusal(410, ended, Map.of("Set-Cookie", HttpShareRules.clearCookie(shareId)));
        }
        if (HttpShareRules.ACCESS_READ.equals(share.getAccess())) {
            if (!HttpShareRules.READ_METHODS.contains(method)) {
                return new Refusal(405, HttpShareRules.CODE_METHOD_NOT_ALLOWED, Map.of("Allow", "GET, HEAD"));
            }
            if (upgrade) {
                return refusal(403, HttpShareRules.CODE_SCOPE_DENIED);
            }
        }
        if (!HttpShareRules.pathInScope(share.getPathPrefix(), relativePath)) {
            return refusal(403, HttpShareRules.CODE_SCOPE_DENIED);
        }
        HttpShareStreamRegistry.InFlight stream = streams.tryAcquire(shareId, share.getExpiresAt());
        if (stream == null) {
            return new Refusal(429, HttpShareRules.CODE_BUSY, Map.of("Retry-After", "1"));
        }
        long waitMs = runtime.shareLimiter().tryAcquire(shareId, nowMs);
        if (waitMs > 0) {
            stream.release();
            return new Refusal(429, HttpShareRules.CODE_RATE_LIMITED,
                    Map.of("Retry-After", Long.toString(GcraRateLimiter.retryAfterSeconds(waitMs))));
        }
        HttpRouteMapping route = world.route();
        return new Admission(shareId, share.getAccess(), route.getId(), world.client().getClientName(),
                route.getRoute(), relativePath, route.getTargetBaseUrl(),
                Boolean.TRUE.equals(route.getPathRewriteEnabled()), stream);
    }

    // =============================================================================================
    // Hooks: called inside the transaction of the change they describe (spec section 7.3)

    public static String exposure(HttpRouteMapping route) {
        if (!route.isEnabled()) {
            return HttpShareRules.EXPOSURE_DISABLED;
        }
        return Boolean.TRUE.equals(route.getAuthEnabled())
                ? HttpShareRules.EXPOSURE_PROTECTED : HttpShareRules.EXPOSURE_PUBLIC;
    }

    public void onRouteCreated(String actor, HttpRouteMapping route) {
        audit(tenantOf(route), runtime.nowSeconds(), actor, HttpShareRules.AUDIT_ROUTE_CREATED, route.getId(), null,
                Map.of("exposure", exposure(route)));
    }

    /**
     * Records the exposure and credential changes of an updated route and ends its shares when it
     * is no longer protected. Renaming, retargeting or a new password never touch shares.
     */
    public void onRouteUpdated(String actor, HttpRouteMapping route, String exposureBefore, boolean credentialsChanged) {
        long now = runtime.nowSeconds();
        String tenantId = tenantOf(route);
        String after = exposure(route);
        if (!after.equals(exposureBefore)) {
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("from", exposureBefore);
            detail.put("to", after);
            audit(tenantId, now, actor, HttpShareRules.AUDIT_ROUTE_EXPOSURE_CHANGED, route.getId(), null, detail);
        }
        if (credentialsChanged) {
            audit(tenantId, now, actor, HttpShareRules.AUDIT_ROUTE_CREDENTIALS_CHANGED, route.getId(), null, Map.of());
        }
        if (!HttpShareRules.EXPOSURE_PROTECTED.equals(after)) {
            String reason = HttpShareRules.EXPOSURE_DISABLED.equals(after)
                    ? HttpShareRules.REASON_ROUTE_DISABLED : HttpShareRules.REASON_ROUTE_MADE_PUBLIC;
            revokeActive(List.of(route.getId()), now, actor, reason);
        }
    }

    public void onRouteDeleted(String actor, HttpRouteMapping route) {
        long now = runtime.nowSeconds();
        audit(tenantOf(route), now, actor, HttpShareRules.AUDIT_ROUTE_DELETED, route.getId(), null,
                Map.of("exposure", exposure(route)));
        revokeActive(List.of(route.getId()), now, actor, HttpShareRules.REASON_ROUTE_DELETED);
    }

    public void onClientDisabled(String actor, ClientAccount client) {
        List<Long> routeIds = routes.findByClientIdOrderByIdDesc(client.getId()).stream()
                .map(HttpRouteMapping::getId).toList();
        revokeActive(routeIds, runtime.nowSeconds(), actor, HttpShareRules.REASON_CLIENT_DISABLED);
    }

    /**
     * A client is being deleted together with its routes: one {@code route.deleted} per route in
     * ascending id, then every active share of those routes ends. The caller deletes the rows.
     */
    public void onClientDeleted(String actor, List<HttpRouteMapping> clientRoutes) {
        long now = runtime.nowSeconds();
        List<HttpRouteMapping> ordered = new ArrayList<>(clientRoutes);
        ordered.sort((left, right) -> Long.compare(left.getId(), right.getId()));
        for (HttpRouteMapping route : ordered) {
            audit(tenantOf(route), now, actor, HttpShareRules.AUDIT_ROUTE_DELETED, route.getId(), null,
                    Map.of("exposure", exposure(route)));
        }
        revokeActive(ordered.stream().map(HttpRouteMapping::getId).toList(), now, actor,
                HttpShareRules.REASON_CLIENT_DELETED);
    }

    /**
     * A user was disabled, deleted or had the role changed: the user's own active shares end when
     * the creator can no longer manage their route.
     */
    public void onUserChanged(String actor, String tenantId, String username) {
        entityManager.flush();
        long now = runtime.nowSeconds();
        List<HttpShare> owned = shares
                .findByTenantIdAndCreatedByAndRevokedAtIsNullAndExpiresAtGreaterThanOrderByCreatedAtAscShareIdAsc(
                        tenantId, username, now);
        for (HttpShare share : owned) {
            if (HttpShareRules.REASON_CREATOR_LOST_ACCESS.equals(lapseReason(loadWorld(share)))) {
                revokeShare(share, now, actor, HttpShareRules.REASON_CREATOR_LOST_ACCESS);
            }
        }
    }

    private void revokeActive(Collection<Long> routeIds, long now, String actor, String reason) {
        if (routeIds.isEmpty()) {
            return;
        }
        List<HttpShare> active = shares
                .findByRouteIdInAndRevokedAtIsNullAndExpiresAtGreaterThanOrderByCreatedAtAscShareIdAsc(routeIds, now);
        for (HttpShare share : active) {
            revokeShare(share, now, actor, reason);
        }
    }

    // =============================================================================================
    // Sweep and in-flight streams (spec sections 6.6 and 7.5)

    @Scheduled(initialDelayString = "${specus.http-share.sweep-initial-delay-ms:5000}",
            fixedDelayString = "${specus.http-share.sweep-interval-ms:30000}")
    public void scheduledSweep() {
        if (!backgroundEnabled) {
            return;
        }
        try {
            sweep();
        } catch (RuntimeException error) {
            log.warn("[http-share] sweep failed: {}", error.toString());
        }
    }

    /**
     * Records each expiry once (stamped with expiresAt, in expiry order), revokes active shares
     * that lapsed without a hook, then drops rows past their retention.
     */
    public void sweep() {
        long now = runtime.nowSeconds();
        transactions.executeWithoutResult(status -> {
            for (HttpShare share : shares
                    .findByRevokedAtIsNullAndExpiryRecordedAndExpiresAtLessThanEqualOrderByExpiresAtAscShareIdAsc(0, now)) {
                if (shares.markExpiryRecorded(share.getShareId()) == 1) {
                    audit(share.getTenantId(), share.getExpiresAt(), null, HttpShareRules.AUDIT_SHARE_EXPIRED,
                            share.getRouteId(), share.getShareId(), Map.of());
                }
            }
        });
        transactions.executeWithoutResult(status -> {
            for (HttpShare share : shares.findByRevokedAtIsNullAndExpiresAtGreaterThanOrderByCreatedAtAscShareIdAsc(now)) {
                String reason = lapseReason(loadWorld(share));
                if (reason != null) {
                    revokeShare(share, now, null, reason);
                }
            }
        });
        transactions.executeWithoutResult(status -> {
            shares.deleteEndedBefore(now - HttpShareRules.SHARE_RETENTION_DAYS * DAY_SECONDS);
            audits.deleteOlderThan(now - HttpShareRules.AUDIT_RETENTION_DAYS * DAY_SECONDS);
        });
    }

    @PostConstruct
    void startStreamTicker() {
        if (!backgroundEnabled) {
            return;
        }
        streamTicker = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "http-share-streams");
            thread.setDaemon(true);
            return thread;
        });
        streamTicker.scheduleWithFixedDelay(this::tickStreams, HttpShareRules.STREAM_EXPIRY_TICK_MS,
                HttpShareRules.STREAM_EXPIRY_TICK_MS, TimeUnit.MILLISECONDS);
    }

    @PreDestroy
    void stopStreamTicker() {
        if (streamTicker != null) {
            streamTicker.shutdownNow();
        }
    }

    /** Every second: cut streams of expired shares; every two seconds: recheck the database. */
    void tickStreams() {
        try {
            streams.cutExpired(runtime.nowMillis());
            long nowNanos = System.nanoTime();
            if (nowNanos - lastRecheckNanos >= TimeUnit.MILLISECONDS.toNanos(HttpShareRules.STREAM_RECHECK_INTERVAL_MS)) {
                lastRecheckNanos = nowNanos;
                recheckInFlight();
            }
        } catch (RuntimeException error) {
            log.warn("[http-share] stream tick failed: {}", error.toString());
        }
    }

    /**
     * Re-reads every share that has streams on this instance (one query each) and cuts them when
     * it ended or lapsed; a revocation on another instance therefore stops them within seconds.
     */
    public void recheckInFlight() {
        for (String shareId : streams.sharesInFlight()) {
            try {
                ShareWorld world = transactions.execute(status -> shares.findById(shareId).map(this::loadWorld).orElse(null));
                if (world == null) {
                    streams.cut(shareId);
                    continue;
                }
                String ended = endedCode(world, runtime.nowSeconds());
                if (ended != null) {
                    streams.cut(shareId);
                }
            } catch (RuntimeException error) {
                log.warn("[http-share] in-flight recheck of share {} failed: {}", shareId, error.toString());
            }
        }
    }

    // =============================================================================================
    // Shared pieces

    /**
     * The ended state of a share whose token was proven, or null while it may be used. A share
     * that is neither revoked nor expired but whose route, client or creator no longer allows it
     * is revoked on the spot (read-time revocation), so it can never come back to life.
     */
    private String endedCode(ShareWorld world, long now) {
        HttpShare share = world.share();
        if (share.getRevokedAt() != null) {
            return HttpShareRules.CODE_REVOKED;
        }
        if (share.getExpiresAt() <= now) {
            return HttpShareRules.CODE_EXPIRED;
        }
        String reason = lapseReason(world);
        if (reason == null) {
            return null;
        }
        try {
            transactions.executeWithoutResult(status -> revokeShare(share, now, null, reason));
        } catch (RuntimeException error) {
            // Still ended: the next reader or the sweep retries the conditional update.
            log.warn("[http-share] read-time revocation of share {} failed: {}", share.getShareId(), error.toString());
            streams.cut(share.getShareId());
        }
        return HttpShareRules.CODE_REVOKED;
    }

    /**
     * Read-time revocation for the management views: a share that is still within its validity but
     * lapsed is revoked before it is shown, so a list never shows an unusable share as active.
     * Returns the share as it is stored afterwards.
     */
    private HttpShare revokeIfLapsed(HttpShare share, ManagedRoute managed, long now) {
        if (!isActive(share, now)) {
            return share;
        }
        String reason = lapseReason(new ShareWorld(share, managed.route(), managed.client(),
                read(() -> lookupActor(share.getTenantId(), share.getCreatedBy()))));
        if (reason == null || revokeShare(share, now, null, reason)) {
            return share;
        }
        return reload(share);
    }

    /**
     * Ends an active share with a conditional update; only when this call changed the row is the
     * {@code share.revoked} entry written. The share's streams on this instance are cut once the
     * surrounding transaction commits.
     */
    private boolean revokeShare(HttpShare share, long now, String actor, String reason) {
        detach(share);
        int updated = shares.revokeIfActive(share.getShareId(), now, actor, reason);
        if (updated != 1) {
            return false;
        }
        share.setRevokedAt(now);
        share.setRevokedBy(actor);
        share.setRevokeReason(reason);
        audit(share.getTenantId(), now, actor, HttpShareRules.AUDIT_SHARE_REVOKED, share.getRouteId(),
                share.getShareId(), Map.of("reason", reason));
        cutAfterCommit(share.getShareId());
        return true;
    }

    private void cutAfterCommit(String shareId) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    streams.cut(shareId);
                }
            });
        } else {
            streams.cut(shareId);
        }
    }

    private String lapseReason(ShareWorld world) {
        HttpShare share = world.share();
        HttpRouteMapping route = world.route();
        if (route == null || !tenantOf(route).equals(share.getTenantId())) {
            return HttpShareRules.REASON_ROUTE_DELETED;
        }
        ClientAccount client = world.client();
        if (client == null) {
            return HttpShareRules.REASON_CLIENT_DELETED;
        }
        if (!client.isEnabled()) {
            return HttpShareRules.REASON_CLIENT_DISABLED;
        }
        String state = exposure(route);
        if (HttpShareRules.EXPOSURE_DISABLED.equals(state)) {
            return HttpShareRules.REASON_ROUTE_DISABLED;
        }
        if (HttpShareRules.EXPOSURE_PUBLIC.equals(state)) {
            return HttpShareRules.REASON_ROUTE_MADE_PUBLIC;
        }
        if (!canManage(world.creator(), route, client)) {
            return HttpShareRules.REASON_CREATOR_LOST_ACCESS;
        }
        return null;
    }

    /** Same tenant, enabled, and a tenant admin or the owner of the route's client, evaluated now. */
    private boolean canManage(Actor actor, HttpRouteMapping route, ClientAccount client) {
        if (actor == null || !actor.tenantId().equals(tenantOf(route))) {
            return false;
        }
        return actor.admin() || (client != null && Objects.equals(client.getOwnerUsername(), actor.username()));
    }

    private Actor lookupActor(ManagementContext context) {
        return context == null ? null : lookupActor(context.tenant().tenantId(), context.username());
    }

    /**
     * Re-reads a user from the database (enabled, role, tenant). The configured built-in
     * administrator has no row: it counts as an enabled ADMIN of the configured tenant whenever the
     * server would currently accept it as a principal.
     */
    private Actor lookupActor(String tenantId, String username) {
        if (!StringUtils.hasText(tenantId) || !StringUtils.hasText(username)) {
            return null;
        }
        String name = username.trim();
        String defaultTenant = TenantContext.normalize(authProperties.getTenantId());
        if (name.equalsIgnoreCase(authProperties.getUsername()) && tenantId.equals(defaultTenant)) {
            boolean accepted = authProperties.isPasswordLoginEnabled() && StringUtils.hasText(authProperties.getPassword());
            return accepted ? new Actor(authProperties.getUsername(), defaultTenant, true) : null;
        }
        return users.findByTenantIdAndLoginNameNormalized(tenantId, name.toLowerCase(Locale.ROOT))
                .filter(ManagementUser::isEnabled)
                .map(user -> new Actor(
                        StringUtils.hasText(user.getLoginName()) ? user.getLoginName() : user.getUsername(),
                        TenantContext.normalize(user.getTenantId()),
                        user.getRole() == ManagementRole.ADMIN))
                .orElse(null);
    }

    private ManagedRoute requireManagedRoute(ManagementContext context, Long routeId) {
        HttpRouteMapping route;
        ClientAccount client;
        Actor actor;
        try {
            route = routeId == null ? null : routes.findById(routeId).orElse(null);
            client = route == null ? null : clients.findById(route.getClientId()).orElse(null);
            actor = lookupActor(context);
        } catch (RuntimeException readFailure) {
            throw unavailable(readFailure);
        }
        if (route == null || !canManage(actor, route, client)) {
            throw problem(404, HttpShareRules.CODE_ROUTE_NOT_FOUND);
        }
        return new ManagedRoute(route, client, actor);
    }

    private HttpShare requireShareOfRoute(ManagedRoute managed, String shareId) {
        HttpShare share = HttpShareRules.isShareId(shareId)
                ? read(() -> shares.findById(shareId).orElse(null)) : null;
        if (share == null || !share.getRouteId().equals(managed.route().getId())
                || !share.getTenantId().equals(tenantOf(managed.route()))) {
            throw problem(404, HttpShareRules.CODE_NOT_FOUND);
        }
        return share;
    }

    private ShareWorld loadWorldOrUnavailable(String shareId) {
        try {
            return transactions.execute(status -> shares.findById(shareId).map(this::loadWorld).orElse(null));
        } catch (RuntimeException readFailure) {
            throw unavailable(readFailure);
        }
    }

    private ShareWorld loadWorld(HttpShare share) {
        HttpRouteMapping route = routes.findById(share.getRouteId()).orElse(null);
        ClientAccount client = route == null ? null : clients.findById(route.getClientId()).orElse(null);
        return new ShareWorld(share, route, client, lookupActor(share.getTenantId(), share.getCreatedBy()));
    }

    private HttpShare reload(HttpShare share) {
        detach(share);
        return shares.findById(share.getShareId()).orElse(share);
    }

    private void detach(HttpShare share) {
        if (entityManager.contains(share)) {
            entityManager.detach(share);
        }
    }

    private Credentials newUniqueCredentials() {
        for (int attempt = 0; attempt < 8; attempt++) {
            Credentials credentials = HttpShareRules.newCredentials(runtime.random());
            if (!shares.existsById(credentials.shareId())) {
                return credentials;
            }
        }
        throw problem(503, HttpShareRules.CODE_UNAVAILABLE);
    }

    private void audit(String tenantId, long at, String actor, String action, Long routeId, String shareId,
                       Map<String, Object> detail) {
        HttpAccessAudit entry = new HttpAccessAudit();
        entry.setTenantId(tenantId);
        entry.setOccurredAt(at);
        entry.setActor(actor);
        entry.setAction(action);
        entry.setRouteId(routeId);
        entry.setShareId(shareId);
        try {
            entry.setDetailJson(JSON.writeValueAsString(detail));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("audit detail is not serializable", e);
        }
        audits.save(entry);
    }

    private static boolean isActive(HttpShare share, long now) {
        return share.getRevokedAt() == null && share.getExpiresAt() > now;
    }

    private static Map<String, Object> view(HttpShare share, long now) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("shareId", share.getShareId());
        view.put("routeId", share.getRouteId());
        view.put("label", share.getLabel());
        view.put("access", share.getAccess());
        view.put("pathPrefix", share.getPathPrefix());
        view.put("sharePath", HttpShareRules.cookiePath(share.getShareId()));
        view.put("createdAt", stamp(share.getCreatedAt()));
        view.put("createdBy", share.getCreatedBy());
        view.put("expiresAt", stamp(share.getExpiresAt()));
        view.put("status", share.getRevokedAt() != null ? "revoked"
                : share.getExpiresAt() <= now ? "expired" : "active");
        view.put("revokedAt", share.getRevokedAt() == null ? null : stamp(share.getRevokedAt()));
        view.put("revokedBy", share.getRevokedBy());
        view.put("revokeReason", share.getRevokeReason());
        return view;
    }

    private static Map<String, Object> auditView(HttpAccessAudit row) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("auditId", row.getId());
        view.put("at", stamp(row.getOccurredAt()));
        view.put("actor", row.getActor());
        view.put("action", row.getAction());
        view.put("routeId", row.getRouteId());
        view.put("shareId", row.getShareId());
        JsonNode detail = parseJson(row.getDetailJson().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        view.put("detail", detail == null ? JSON.createObjectNode() : detail);
        return view;
    }

    /** {@code YYYY-MM-DDTHH:MM:SSZ}: whole seconds, no fraction. */
    public static String stamp(long epochSeconds) {
        return DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochSecond(epochSeconds));
    }

    private static String tenantOf(HttpRouteMapping route) {
        return TenantContext.normalize(route.getTenantId());
    }

    // ---------------------------------------------------------------------------------------------
    // Request validation

    private static CreateFields validateCreate(byte[] body) {
        JsonNode node = parseJson(body);
        if (node == null || !node.isObject()) {
            throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
        }
        for (Iterator<String> names = node.fieldNames(); names.hasNext(); ) {
            if (!CREATE_FIELDS.contains(names.next())) {
                throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
            }
        }
        JsonNode seconds = node.get("expiresInSeconds");
        // A JSON integer only: no string, boolean, or number written with a fraction or exponent.
        if (seconds == null || !seconds.isIntegralNumber() || !seconds.canConvertToLong()
                || seconds.longValue() < HttpShareRules.MIN_EXPIRES_SECONDS
                || seconds.longValue() > HttpShareRules.MAX_EXPIRES_SECONDS) {
            throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
        }
        String access = HttpShareRules.ACCESS_READ;
        if (node.has("access")) {
            JsonNode value = node.get("access");
            if (!value.isTextual() || !(value.textValue().equals(HttpShareRules.ACCESS_READ)
                    || value.textValue().equals(HttpShareRules.ACCESS_FULL))) {
                throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
            }
            access = value.textValue();
        }
        String prefix = "/";
        if (node.has("pathPrefix")) {
            JsonNode value = node.get("pathPrefix");
            prefix = value.isTextual() ? HttpShareRules.canonicalPrefix(value.textValue()) : null;
            if (prefix == null) {
                throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
            }
        }
        String label = null;
        JsonNode labelNode = node.get("label");
        if (labelNode != null && !labelNode.isNull()) {
            if (!labelNode.isTextual()) {
                throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
            }
            label = stripSpaces(labelNode.textValue());
            if (label.chars().anyMatch(ch -> ch < 0x20 || ch == 0x7F)
                    || label.codePointCount(0, label.length()) > HttpShareRules.LABEL_MAX_CODE_POINTS) {
                throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
            }
            label = label.isEmpty() ? null : label;
        }
        return new CreateFields((int) seconds.longValue(), access, prefix, label);
    }

    private static boolean isEmptyObjectBody(byte[] body) {
        if (body == null || new String(body, java.nio.charset.StandardCharsets.UTF_8).isBlank()) {
            return true;
        }
        JsonNode node = parseJson(body);
        return node != null && node.isObject() && node.isEmpty();
    }

    private static boolean isJsonMediaType(String contentType) {
        if (contentType == null) {
            return false;
        }
        int semicolon = contentType.indexOf(';');
        String mediaType = (semicolon < 0 ? contentType : contentType.substring(0, semicolon)).trim();
        return mediaType.toLowerCase(Locale.ROOT).equals("application/json");
    }

    private static JsonNode parseJson(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            return JSON.readTree(body);
        } catch (java.io.IOException | RuntimeException invalid) {
            return null;
        }
    }

    private static String stripSpaces(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && value.charAt(start) == ' ') {
            start++;
        }
        while (end > start && value.charAt(end - 1) == ' ') {
            end--;
        }
        return value.substring(start, end);
    }

    /** A route id from the path; anything but a positive integer is answered as a missing route. */
    private static Long parseId(String text) {
        if (text == null || !text.matches("[0-9]{1,18}")) {
            return null;
        }
        long value = Long.parseLong(text);
        return value > 0 ? value : null;
    }

    private static Long parseOptionalPositive(String text) {
        if (text == null) {
            return null;
        }
        Long value = parseId(text);
        if (value == null) {
            throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
        }
        return value;
    }

    private static int parseLimit(String text) {
        if (text == null) {
            return DEFAULT_AUDIT_LIMIT;
        }
        if (!text.matches("[0-9]{1,3}")) {
            throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
        }
        int limit = Integer.parseInt(text);
        if (limit < 1 || limit > MAX_AUDIT_LIMIT) {
            throw problem(400, HttpShareRules.CODE_REQUEST_INVALID);
        }
        return limit;
    }

    private static Refusal refusal(int status, String code) {
        return new Refusal(status, code, Map.of());
    }

    static ShareProblem problem(int status, String code) {
        return new ShareProblem(status, code, Map.of());
    }

    static ShareProblem problem(int status, String code, Map<String, String> headers) {
        return new ShareProblem(status, code, headers);
    }

    private static ShareProblem unavailable(RuntimeException cause) {
        log.warn("[http-share] store read failed: {}", cause.toString());
        return problem(503, HttpShareRules.CODE_UNAVAILABLE);
    }

    private static <T> T read(java.util.function.Supplier<T> reader) {
        try {
            return reader.get();
        } catch (ShareProblem problem) {
            throw problem;
        } catch (RuntimeException readFailure) {
            throw unavailable(readFailure);
        }
    }

    /** Runs an API operation; a storage failure that is not already a share answer becomes 503. */
    private static ApiResult guarded(java.util.function.Supplier<ApiResult> operation) {
        try {
            return operation.get();
        } catch (ShareProblem problem) {
            throw problem;
        } catch (RuntimeException failure) {
            throw unavailable(failure);
        }
    }
}
