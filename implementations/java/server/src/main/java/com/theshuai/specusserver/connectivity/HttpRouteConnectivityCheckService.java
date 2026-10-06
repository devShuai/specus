package com.theshuai.specusserver.connectivity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.common.protocol.HttpRouteFailure;
import com.theshuai.specusserver.connectivity.ConnectivityProbe.Answer;
import com.theshuai.specusserver.management.security.ManagementContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * {@code POST /api/admin/http-routes/{routeId}/connectivity-check}: one bounded end-to-end check of
 * one route the caller chose (protocol/spec/service-connectivity-check.md).
 *
 * <p>Refusals come in the order of section 3.2 and none of them takes rate: invalid body, route
 * unreadable, route not visible, the route already being checked, the process at its 32 concurrent
 * checks, then the rate limit. A check that runs answers 200 whatever stage it stopped at: the
 * four stages in fixed order, each decided at the first moment it can be, the first stage that does
 * not pass ending the check.
 *
 * <p>Nothing the target said beyond the status class reaches the answer or the log: no address,
 * no path, no headers, no body, no exact status and no RST reason.
 */
@Service
@Slf4j
public class HttpRouteConnectivityCheckService {
    public static final long BUDGET_MS = 10_000;
    public static final int MAX_CONCURRENT_CHECKS = 32;
    public static final String USER_AGENT = "specus-connectivity-check/1";
    static final long REFUSAL_LOG_INTERVAL_MS = 60_000;
    static final int REFUSAL_LOG_MAX_ENTRIES = 10_000;

    public static final String REQUEST_INVALID = "CHECK_REQUEST_INVALID";
    public static final String UNAVAILABLE = "CHECK_UNAVAILABLE";
    public static final String TARGET_NOT_FOUND = "CHECK_TARGET_NOT_FOUND";
    public static final String IN_PROGRESS = "CHECK_IN_PROGRESS";
    public static final String BUSY = "CHECK_BUSY";
    public static final String RATE_LIMITED = "CHECK_RATE_LIMITED";

    private static final String CONFIGURED = "configured";
    private static final String DEVICE_ONLINE = "device-online";
    private static final String TARGET_REACHABLE = "target-reachable";
    private static final String ACCESS_SUCCEEDED = "access-succeeded";
    private static final List<String> STAGES = List.of(CONFIGURED, DEVICE_ONLINE, TARGET_REACHABLE, ACCESS_SUCCEEDED);
    private static final String PASSED = "passed";
    private static final String FAILED = "failed";
    private static final String UNVERIFIED = "unverified";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom REQUEST_IDS = new SecureRandom();

    private final ConnectivityCheckTargets targets;
    private final ConnectivityProbe probe;
    private final ConnectivityCheckClock clock;
    private final ConnectivityCheckRateLimiter rateLimiter;
    private final Set<String> routesInFlight = ConcurrentHashMap.newKeySet();
    private final AtomicInteger checksInFlight = new AtomicInteger();
    private final Map<String, Long> refusalsLogged = new HashMap<>();

    @Autowired
    public HttpRouteConnectivityCheckService(ConnectivityCheckTargets targets, ConnectivityProbe probe) {
        this(targets, probe, ConnectivityCheckClock.SYSTEM);
    }

    public HttpRouteConnectivityCheckService(ConnectivityCheckTargets targets,
                                             ConnectivityProbe probe,
                                             ConnectivityCheckClock clock) {
        this(targets, probe, clock, new ConnectivityCheckRateLimiter());
    }

    HttpRouteConnectivityCheckService(ConnectivityCheckTargets targets,
                                      ConnectivityProbe probe,
                                      ConnectivityCheckClock clock,
                                      ConnectivityCheckRateLimiter rateLimiter) {
        this.targets = targets;
        this.probe = probe;
        this.clock = clock;
        this.rateLimiter = rateLimiter;
    }

    /**
     * Runs the whole request: {@code caller} resolves the management session and throws for a
     * request without a valid one, before anything else is looked at.
     *
     * @param routeId the path segment as sent; a non-numeric or non-positive id is not found
     * @param body    the request body; at most one byte past the limit is read
     */
    public Response check(Supplier<ManagementContext> caller, String routeId, InputStream body) {
        long started = clock.monotonicMillis();
        Instant checkedAt = clock.now();
        ManagementContext context = caller.get();

        Optional<String> path;
        try {
            path = ConnectivityCheckRequest.probePath(ConnectivityCheckRequest.readBody(body));
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
        if (path.isEmpty()) {
            return Response.refusal(400, REQUEST_INVALID, null);
        }
        long id = parseRouteId(routeId);
        if (id <= 0) {
            return Response.refusal(404, TARGET_NOT_FOUND, null);
        }
        Optional<ConnectivityCheckTargets.Target> target;
        try {
            target = targets.findVisible(context, id);
        } catch (RuntimeException unreadable) {
            log.warn("[connectivity-check] tenant={} user={} route={} records unreadable: {}",
                    context.tenant().tenantId(), context.username(), id, unreadable.getClass().getSimpleName());
            return Response.refusal(503, UNAVAILABLE, 1L);
        }
        if (target.isEmpty()) {
            return Response.refusal(404, TARGET_NOT_FOUND, null);
        }

        String tenantId = context.tenant().tenantId();
        String routeKey = tenantId + '\n' + id;
        if (!routesInFlight.add(routeKey)) {
            return Response.refusal(429, IN_PROGRESS, 1L);
        }
        try {
            if (checksInFlight.incrementAndGet() > MAX_CONCURRENT_CHECKS) {
                checksInFlight.decrementAndGet();
                return Response.refusal(503, BUSY, 1L);
            }
            try {
                String userKey = tenantId + '\n' + context.username();
                ConnectivityCheckRateLimiter.Admission admission =
                        rateLimiter.tryAcquire(routeKey, userKey, clock.monotonicMillis());
                if (admission.outcome() == ConnectivityCheckRateLimiter.Outcome.LIMITED) {
                    long retryAfter = admission.retryAfterSeconds();
                    if (shouldLogRefusal(userKey)) {
                        log.info("[connectivity-check] tenant={} user={} route={} refused code={} retryAfter={}",
                                tenantId, context.username(), id, RATE_LIMITED, retryAfter);
                    }
                    return Response.refusal(429, RATE_LIMITED, retryAfter);
                }
                if (admission.outcome() == ConnectivityCheckRateLimiter.Outcome.FULL) {
                    return Response.refusal(503, BUSY, 1L);
                }
                Result result = run(target.get(), path.get(), started);
                log.info("[connectivity-check] tenant={} user={} route={} outcome={} stage={} code={} totalMs={}",
                        tenantId, context.username(), id, result.outcome(),
                        result.stoppedAt() == null ? "-" : result.stoppedAt(), result.code(), result.totalMs());
                return Response.ok(result.toJson(id, checkedAt));
            } finally {
                checksInFlight.decrementAndGet();
            }
        } finally {
            routesInFlight.remove(routeKey);
        }
    }

    private Result run(ConnectivityCheckTargets.Target target, String path, long started) {
        Result result = new Result();
        // Stage 1: the server's own records.
        if (!target.routeEnabled()) {
            return result.decide(CONFIGURED, FAILED, "ROUTE_DISABLED", 0);
        }
        if (!target.clientEnabled()) {
            return result.decide(CONFIGURED, FAILED, "CLIENT_DISABLED", 0);
        }
        if (!target.targetValid()) {
            return result.decide(CONFIGURED, FAILED, "ROUTE_TARGET_INVALID", 0);
        }
        result.decide(CONFIGURED, PASSED, "CONFIGURED", 0);

        // Stage 2 precondition: an authenticated control session and its data connection, now.
        ConnectivityProbe.DeviceLink link = probe.link(target.clientName());
        if (link instanceof ConnectivityProbe.Offline) {
            return result.decide(DEVICE_ONLINE, FAILED, "DEVICE_OFFLINE", 0);
        }
        if (!(link instanceof ConnectivityProbe.Online online)) {
            return result.decide(DEVICE_ONLINE, FAILED, "DEVICE_DATA_CHANNEL_DOWN", 0);
        }
        ConnectivityProbe.ProbeChannel channel = online.channel();
        boolean capable = channel.httpRouteCapability() >= HttpRouteFailure.CAPABILITY_VERSION;

        Answer head = ask(result, channel, "HEAD", target.route(), path, started);
        if (head instanceof ConnectivityProbe.NoAnswer) {
            // The stream was written to a live connection: a silent device and a target that never
            // sends a head cannot be told apart within the budget, so the target stage takes it.
            result.decide(DEVICE_ONLINE, PASSED, "DEVICE_ONLINE", BUDGET_MS);
            return result.decide(TARGET_REACHABLE, FAILED, "TARGET_TIMEOUT", BUDGET_MS);
        }
        long at = elapsed(started);
        if (head instanceof ConnectivityProbe.OpenFailed openFailed) {
            return result.decide(DEVICE_ONLINE, FAILED,
                    openFailed.streamLimit() ? "DEVICE_BUSY" : "DEVICE_LINK_LOST", at);
        }
        if (head instanceof ConnectivityProbe.LinkLost) {
            return result.decide(DEVICE_ONLINE, FAILED, "DEVICE_LINK_LOST", at);
        }
        if (head instanceof ConnectivityProbe.Reset reset) {
            HttpRouteFailure failure = capable ? HttpRouteFailure.fromWireName(reset.failure()) : null;
            if (failure == HttpRouteFailure.ROUTE_NOT_LOADED) {
                return result.decide(DEVICE_ONLINE, FAILED, "DEVICE_ROUTE_NOT_LOADED", at);
            }
            result.decide(DEVICE_ONLINE, PASSED, "DEVICE_ONLINE", at);
            if (failure == null) {
                // An older client, no classification, or one this server does not know: the device
                // answered, but nothing says whether the target was ever reached.
                return result.decide(TARGET_REACHABLE, UNVERIFIED, "TARGET_UNVERIFIED", at);
            }
            return result.decide(TARGET_REACHABLE, FAILED, targetCode(failure), at);
        }
        int status = head instanceof ConnectivityProbe.Head answered ? answered.statusCode() : 0;
        result.decide(DEVICE_ONLINE, PASSED, "DEVICE_ONLINE", at);
        if (status < 200 || status > 599) {
            return result.decide(TARGET_REACHABLE, FAILED, "TARGET_PROTOCOL_ERROR", at);
        }
        result.decide(TARGET_REACHABLE, PASSED, "TARGET_ANSWERED", at);
        if (status != 405 && status != 501) {
            return result.access(status, at);
        }

        // The target refused the method: one GET, with what is left of the same budget.
        Answer get = ask(result, channel, "GET", target.route(), path, started);
        if (get instanceof ConnectivityProbe.NoAnswer) {
            return result.decide(ACCESS_SUCCEEDED, FAILED, "ACCESS_NO_ANSWER", BUDGET_MS);
        }
        long getAt = elapsed(started);
        if (get instanceof ConnectivityProbe.Head answered
                && answered.statusCode() >= 200 && answered.statusCode() <= 599) {
            return result.access(answered.statusCode(), getAt);
        }
        // The HEAD proved the target reachable; this request has no status to classify.
        return result.decide(ACCESS_SUCCEEDED, FAILED, "ACCESS_NO_ANSWER", getAt);
    }

    private Answer ask(Result result, ConnectivityProbe.ProbeChannel channel, String method,
                       String route, String path, long started) {
        result.requests.add(method);
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("source", "http");
        metadata.put("phase", "request");
        metadata.put("requestId", HexFormat.of().formatHex(randomBytes(16)));
        metadata.put("method", method);
        metadata.put("route", route);
        metadata.put("relativePath", path);
        metadata.put("rawQuery", "");
        metadata.put("headers", List.of("Accept:*/*", "User-Agent:" + USER_AGENT));
        long remaining = BUDGET_MS - (clock.monotonicMillis() - started);
        return channel.exchange(metadata, Math.max(0, remaining));
    }

    private long elapsed(long started) {
        return Math.min(BUDGET_MS, Math.max(0, clock.monotonicMillis() - started));
    }

    private boolean shouldLogRefusal(String userKey) {
        long now = clock.monotonicMillis();
        synchronized (refusalsLogged) {
            Long last = refusalsLogged.get(userKey);
            if (last != null && now - last < REFUSAL_LOG_INTERVAL_MS) {
                return false;
            }
            if (last == null && refusalsLogged.size() >= REFUSAL_LOG_MAX_ENTRIES) {
                refusalsLogged.values().removeIf(at -> now - at >= REFUSAL_LOG_INTERVAL_MS);
                if (refusalsLogged.size() >= REFUSAL_LOG_MAX_ENTRIES) {
                    return false;
                }
            }
            refusalsLogged.put(userKey, now);
            return true;
        }
    }

    private static String targetCode(HttpRouteFailure failure) {
        return switch (failure) {
            case ROUTE_NOT_LOADED -> "DEVICE_ROUTE_NOT_LOADED";
            case TARGET_INVALID -> "TARGET_ADDRESS_INVALID";
            case CONNECT_REFUSED -> "TARGET_CONNECT_REFUSED";
            case CONNECT_TIMEOUT -> "TARGET_CONNECT_TIMEOUT";
            case DNS_FAILED -> "TARGET_DNS_FAILED";
            case TLS_FAILED -> "TARGET_TLS_FAILED";
            case UNREACHABLE -> "TARGET_UNREACHABLE";
            case PROTOCOL_ERROR -> "TARGET_PROTOCOL_ERROR";
        };
    }

    private static long parseRouteId(String routeId) {
        if (routeId == null) {
            return -1;
        }
        try {
            return Long.parseLong(routeId);
        } catch (NumberFormatException notNumeric) {
            return -1;
        }
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        REQUEST_IDS.nextBytes(bytes);
        return bytes;
    }

    /**
     * What the endpoint answers: the status, the JSON body, and for a refusal that can be retried
     * the Retry-After seconds. Every answer is {@code Cache-Control: private, no-store}.
     */
    public record Response(int status, byte[] body, Long retryAfterSeconds) {
        static Response refusal(int status, String code, Long retryAfterSeconds) {
            ObjectNode body = JSON.createObjectNode();
            body.put("code", code);
            return new Response(status, bytes(body), retryAfterSeconds);
        }

        static Response ok(ObjectNode body) {
            return new Response(200, bytes(body), null);
        }

        private static byte[] bytes(ObjectNode body) {
            try {
                return JSON.writeValueAsBytes(body);
            } catch (JsonProcessingException impossible) {
                throw new IllegalStateException(impossible);
            }
        }
    }

    /** The decided stages of one check, in order, and the requests sent to the device. */
    private static final class Result {
        private final List<Stage> stages = new ArrayList<>();
        private final List<String> requests = new ArrayList<>();
        private Integer decidingStatus;

        private Result decide(String stage, String result, String code, long atMs) {
            stages.add(new Stage(stage, result, code, atMs));
            return this;
        }

        /** The access stage from the status of the request that decides it. */
        private Result access(int status, long atMs) {
            decidingStatus = status;
            if (status >= 200 && status <= 399) {
                return decide(ACCESS_SUCCEEDED, PASSED, "ACCESS_OK", atMs);
            }
            if (status == 401 || status == 403 || status == 407) {
                // The target answered but wants its own credentials; the check never sends any.
                return decide(ACCESS_SUCCEEDED, UNVERIFIED, "ACCESS_AUTH_REQUIRED", atMs);
            }
            if (status == 404 || status == 410) {
                return decide(ACCESS_SUCCEEDED, FAILED, "ACCESS_NOT_FOUND", atMs);
            }
            if (status <= 499) {
                return decide(ACCESS_SUCCEEDED, FAILED, "ACCESS_CLIENT_ERROR", atMs);
            }
            return decide(ACCESS_SUCCEEDED, FAILED, "ACCESS_SERVER_ERROR", atMs);
        }

        private Stage last() {
            return stages.get(stages.size() - 1);
        }

        private String outcome() {
            return switch (last().result()) {
                case PASSED -> "succeeded";
                case FAILED -> "failed";
                default -> "unverified";
            };
        }

        private String stoppedAt() {
            return PASSED.equals(last().result()) ? null : last().stage();
        }

        private String code() {
            return last().code();
        }

        private long totalMs() {
            return last().atMs();
        }

        private ObjectNode toJson(long routeId, Instant checkedAt) {
            ObjectNode body = JSON.createObjectNode();
            body.put("schemaVersion", 1);
            body.put("kind", "http-route");
            body.put("routeId", routeId);
            body.put("checkedAt", DateTimeFormatter.ISO_INSTANT.format(checkedAt.truncatedTo(ChronoUnit.SECONDS)));
            body.put("outcome", outcome());
            String stoppedAt = stoppedAt();
            if (stoppedAt == null) {
                body.putNull("stoppedAt");
            } else {
                body.put("stoppedAt", stoppedAt);
            }
            body.put("code", code());
            body.put("totalMs", totalMs());
            ArrayNode sent = body.putArray("requests");
            requests.forEach(sent::add);
            ArrayNode entries = body.putArray("stages");
            for (int index = 0; index < STAGES.size(); index++) {
                ObjectNode entry = entries.addObject();
                entry.put("stage", STAGES.get(index));
                if (index < stages.size()) {
                    Stage stage = stages.get(index);
                    entry.put("result", stage.result());
                    entry.put("code", stage.code());
                    entry.put("atMs", stage.atMs());
                } else {
                    entry.put("result", "skipped");
                }
            }
            if (decidingStatus != null) {
                body.put("statusClass", (decidingStatus / 100) + "xx");
            }
            return body;
        }
    }

    private record Stage(String stage, String result, String code, long atMs) {
    }
}
