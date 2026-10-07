package com.theshuai.specusserver.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.httpshare.GcraRateLimiter;
import com.theshuai.specusserver.httpshare.HttpShareRandom;
import com.theshuai.specusserver.httpshare.HttpShareRules;
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
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.management.service.HttpShareService;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.LocalTokenService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.WebSocketSession;

import javax.sql.DataSource;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Replays every section of {@code protocol/test-vectors/temporary-http-share-v1.json} through the
 * real server: the fixture world goes into the SQLite store through the JPA repositories, the
 * share clock and random source are the vector's, creation, exchange and revocation go over HTTP
 * to the running server, visitor requests go through the real share entry and WebSocket handshake
 * with a fake device capturing the NAT OPEN, and lifecycle events go through the real route,
 * client and user management services. Audit rows are compared field by field.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:sqlite::memory:",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false",
                "specus.client-packages.github-release-fallback-enabled=false",
                "specus.env=test",
                "specus.auth.username=root-operator",
                "specus.auth.password=root-operator-password",
                // The vector drives the sweep explicitly; no background work may touch the store.
                "specus.http-share.background-enabled=false"
        }
)
class HttpShareVectorTests {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final JsonNode VECTOR = readVector();
    private static final Instant DEFAULT_NOW = Instant.parse("2026-10-06T08:00:00Z");
    private static final String CLIENT_PREFIX = "vector-client-";

    @Value("${local.server.port}")
    private int port;

    @Autowired private HttpShareRuntime runtime;
    @Autowired private HttpShareStreamRegistry streamRegistry;
    @Autowired private HttpShareService shareService;
    @Autowired private HttpShareController shareController;
    @Autowired private HttpShareWebSocketHandshakeInterceptor shareHandshake;
    @Autowired private WebSocketSpecusHandler webSocketHandler;
    @Autowired private WebSocketStreamRegistry webSocketRegistry;
    @Autowired private HttpShareRepository shareRepository;
    @Autowired private HttpAccessAuditRepository auditRepository;
    @Autowired private HttpRouteMappingRepository routeRepository;
    @Autowired private ClientAccountRepository clientRepository;
    @Autowired private ManagementUserRepository userRepository;
    @Autowired private HttpRouteService routeService;
    @Autowired private ClientAccountService clientService;
    @Autowired private ManagementUserService userService;
    @Autowired private LocalTokenService tokens;
    @Autowired private DataSource dataSource;

    private final MutableClock clock = new MutableClock(DEFAULT_NOW);
    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void installVectorClock() {
        runtime.useClock(clock);
    }

    @AfterEach
    void restoreRuntime() {
        runtime.useClock(null);
        runtime.useRandom(null);
        runtime.exchangeLimiter().clear();
        runtime.shareLimiter().clear();
        streamRegistry.clear();
    }

    // =============================================================================================
    // constants, token, pathPrefix

    @Test
    void constantsMatchTheImplementation() {
        JsonNode constants = VECTOR.get("constants");
        assertThat(constants.get("tokenVersion").asText()).isEqualTo(HttpShareRules.TOKEN_VERSION);
        assertThat(constants.get("shareIdBytes").asInt()).isEqualTo(HttpShareRules.SHARE_ID_BYTES);
        assertThat(constants.get("secretBytes").asInt()).isEqualTo(HttpShareRules.SECRET_BYTES);
        assertThat(constants.get("tokenPattern").asText()).isEqualTo(HttpShareRules.TOKEN_PATTERN.pattern());
        assertThat(constants.get("cookieName").asText()).isEqualTo(HttpShareRules.COOKIE_NAME);
        assertThat(constants.get("maxCookieCandidates").asInt()).isEqualTo(HttpShareRules.MAX_COOKIE_CANDIDATES);
        assertThat(constants.get("sharePathRoot").asText()).isEqualTo(HttpShareRules.SHARE_ROOT);
        assertThat(constants.get("linkRoot").asText()).isEqualTo(HttpShareRules.LINK_ROOT);
        assertThat(constants.get("minExpiresInSeconds").asInt()).isEqualTo(HttpShareRules.MIN_EXPIRES_SECONDS);
        assertThat(constants.get("maxExpiresInSeconds").asInt()).isEqualTo(HttpShareRules.MAX_EXPIRES_SECONDS);
        assertThat(constants.get("maxActiveSharesPerRoute").asInt()).isEqualTo(HttpShareRules.MAX_ACTIVE_PER_ROUTE);
        assertThat(constants.get("labelMaxCodePoints").asInt()).isEqualTo(HttpShareRules.LABEL_MAX_CODE_POINTS);
        assertThat(constants.get("pathPrefixMaxBytes").asInt()).isEqualTo(HttpShareRules.PREFIX_MAX_BYTES);
        assertThat(texts(constants.get("readMethods"))).isEqualTo(HttpShareRules.READ_METHODS);
        assertThat(constants.get("maxConcurrentPerShare").asInt()).isEqualTo(HttpShareRules.MAX_CONCURRENT_PER_SHARE);
        assertThat(constants.get("sweepIntervalMaxSeconds").asInt()).isEqualTo(HttpShareRules.SWEEP_INTERVAL_MAX_SECONDS);
        assertThat(HttpShareRules.SWEEP_INTERVAL_MS).isLessThanOrEqualTo(HttpShareRules.SWEEP_INTERVAL_MAX_SECONDS * 1000L);
        assertThat(constants.get("streamRecheckMaxSeconds").asInt()).isEqualTo(HttpShareRules.STREAM_RECHECK_MAX_SECONDS);
        assertThat(HttpShareRules.STREAM_RECHECK_INTERVAL_MS + HttpShareRules.STREAM_EXPIRY_TICK_MS)
                .isLessThanOrEqualTo(HttpShareRules.STREAM_RECHECK_MAX_SECONDS * 1000L);
        assertThat(constants.get("shareRetentionDays").asInt()).isEqualTo(HttpShareRules.SHARE_RETENTION_DAYS);
        assertThat(constants.get("auditRetentionDays").asInt()).isEqualTo(HttpShareRules.AUDIT_RETENTION_DAYS);
        assertThat(texts(constants.get("revokeReasons"))).isEqualTo(HttpShareRules.REVOKE_REASONS);
        assertThat(texts(constants.get("auditActions"))).isEqualTo(HttpShareRules.AUDIT_ACTIONS);
        JsonNode rate = VECTOR.get("rate");
        assertThat(rate.get("exchange").get("intervalMs").asLong()).isEqualTo(HttpShareRules.EXCHANGE_INTERVAL_MS);
        assertThat(rate.get("exchange").get("burst").asInt()).isEqualTo(HttpShareRules.EXCHANGE_BURST);
        assertThat(rate.get("share").get("intervalMs").asLong()).isEqualTo(HttpShareRules.SHARE_INTERVAL_MS);
        assertThat(rate.get("share").get("burst").asInt()).isEqualTo(HttpShareRules.SHARE_BURST);
        List<String> allCodes = new ArrayList<>();
        VECTOR.get("codes").forEach(section -> allCodes.addAll(texts(section)));
        assertThat(List.of(HttpShareRules.CODE_REQUEST_INVALID, HttpShareRules.CODE_UNAVAILABLE,
                HttpShareRules.CODE_ROUTE_NOT_FOUND, HttpShareRules.CODE_ROUTE_DISABLED,
                HttpShareRules.CODE_CLIENT_DISABLED, HttpShareRules.CODE_ROUTE_PUBLIC,
                HttpShareRules.CODE_LIMIT_REACHED, HttpShareRules.CODE_NOT_FOUND, HttpShareRules.CODE_RATE_LIMITED,
                HttpShareRules.CODE_REVOKED, HttpShareRules.CODE_EXPIRED, HttpShareRules.CODE_METHOD_NOT_ALLOWED,
                HttpShareRules.CODE_SCOPE_DENIED, HttpShareRules.CODE_BUSY)).containsAll(allCodes);
    }

    @TestFactory
    Stream<DynamicTest> token() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode example : VECTOR.get("token").get("examples")) {
            tests.add(DynamicTest.dynamicTest("example " + example.get("shareId").asText(), () -> {
                HttpShareRules.Credentials credentials = HttpShareRules.newCredentials(bytesFrom(
                        example.get("shareIdBytesHex").asText(), example.get("secretBytesHex").asText()));
                assertThat(credentials.shareId()).isEqualTo(example.get("shareId").asText());
                assertThat(credentials.token()).isEqualTo(example.get("token").asText());
                assertThat(credentials.tokenSha256()).isEqualTo(example.get("tokenSha256").asText());
                assertThat(credentials.sharePath()).isEqualTo(example.get("sharePath").asText());
                assertThat(credentials.linkPath()).isEqualTo(example.get("linkPath").asText());
            }));
        }
        int index = 0;
        for (JsonNode parse : VECTOR.get("token").get("parse")) {
            tests.add(DynamicTest.dynamicTest("parse #" + index++, () -> {
                String input = parse.get("input").isNull() ? null : parse.get("input").asText();
                String expected = parse.get("shareId").isNull() ? null : parse.get("shareId").asText();
                assertThat(HttpShareRules.parseToken(input)).as(String.valueOf(input)).isEqualTo(expected);
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> pathPrefix() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode prefix : VECTOR.get("pathPrefix")) {
            JsonNode input = prefix.get("input");
            tests.add(DynamicTest.dynamicTest("prefix " + input, () -> {
                // The create endpoint only canonicalises JSON strings; anything else is rejected.
                String canonical = input.isTextual() ? HttpShareRules.canonicalPrefix(input.asText()) : null;
                String expected = prefix.get("canonical").isNull() ? null : prefix.get("canonical").asText();
                assertThat(canonical).as(input.toString()).isEqualTo(expected);
            }));
        }
        return tests.stream();
    }

    // =============================================================================================
    // create (over HTTP, with the vector's random bytes)

    @TestFactory
    Stream<DynamicTest> create() {
        return cases("create").map(testCase -> DynamicTest.dynamicTest(testCase.get("name").asText(), () -> {
            JsonNode input = testCase.get("input");
            JsonNode expect = testCase.get("expect");
            resetWorld(input);
            clock.set(instant(input, "now"));
            JsonNode newShare = VECTOR.get("newShare");
            runtime.useRandom(bytesFrom(newShare.get("shareIdBytesHex").asText(),
                    newShare.get("secretBytesHex").asText()));
            String path = "/api/admin/http-routes/" + input.get("routeId").asText() + "/shares";
            String bearer = input.path("authenticated").asBoolean(true) ? bearer(input.get("caller").asText()) : null;
            HttpResponse<String> response = withStore(input.path("readable").asBoolean(true),
                    () -> send("POST", path, "application/json", JSON.writeValueAsString(input.get("body")), bearer, Map.of()));

            assertThat(response.statusCode()).as(response.body()).isEqualTo(expect.get("httpStatus").asInt());
            if (expect.has("body")) {
                assertThat(JSON.readTree(response.body())).isEqualTo(expect.get("body"));
                assertThat(response.headers().firstValue("Cache-Control")).hasValue("private, no-store");
                HttpShare stored = shareRepository.findById(newShare.get("shareId").asText()).orElseThrow();
                assertThat(stored.getTokenSha256())
                        .isEqualTo(HttpShareRules.tokenSha256(newShare.get("token").asText()));
                assertThat(stored.getLabel()).isEqualTo(textOrNull(expect.get("body").get("share").get("label")));
            } else if (expect.has("code")) {
                assertThat(JSON.readTree(response.body()).get("code").asText()).isEqualTo(expect.get("code").asText());
                assertThat(shareRepository.findById(newShare.get("shareId").asText())).isEmpty();
            }
            assertAudit(expect.get("audit"), Map.of());
        }));
    }

    /**
     * Concurrent creations on a route one share below the limit: exactly one more share is issued
     * and every other request is refused with {@code SHARE_LIMIT_REACHED}.
     */
    @Test
    void creationsRacingForTheLastSlotStopAtTheLimit() throws Exception {
        resetWorld(JSON.createObjectNode());
        String bearer = bearer("alice");
        String body = "{\"expiresInSeconds\": 3600}";
        String path = "/api/admin/http-routes/42/shares";
        for (int i = 0; i < HttpShareRules.MAX_ACTIVE_PER_ROUTE - 1; i++) {
            HttpResponse<String> seeded = send("POST", path, "application/json", body, bearer, Map.of());
            assertThat(seeded.statusCode()).as(seeded.body()).isEqualTo(201);
        }

        int racers = 8;
        List<CompletableFuture<HttpResponse<String>>> answers = new ArrayList<>();
        for (int i = 0; i < racers; i++) {
            HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + bearer)
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            answers.add(http.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)));
        }
        int created = 0;
        int refused = 0;
        for (CompletableFuture<HttpResponse<String>> answer : answers) {
            HttpResponse<String> response = answer.get(30, TimeUnit.SECONDS);
            assertThat(response.headers().firstValue("Cache-Control")).hasValue("private, no-store");
            if (response.statusCode() == 201) {
                created++;
            } else {
                assertThat(response.statusCode()).as(response.body()).isEqualTo(409);
                assertThat(JSON.readTree(response.body()).get("code").asText())
                        .isEqualTo(HttpShareRules.CODE_LIMIT_REACHED);
                refused++;
            }
        }
        assertThat(created).isEqualTo(1);
        assertThat(refused).isEqualTo(racers - 1);
        assertThat(shareRepository.countByRouteIdAndRevokedAtIsNullAndExpiresAtGreaterThan(42L,
                DEFAULT_NOW.getEpochSecond())).isEqualTo(HttpShareRules.MAX_ACTIVE_PER_ROUTE);
    }

    // =============================================================================================
    // exchange (over HTTP)

    @TestFactory
    Stream<DynamicTest> exchange() {
        return cases("exchange").map(testCase -> DynamicTest.dynamicTest(testCase.get("name").asText(), () -> {
            JsonNode input = testCase.get("input");
            JsonNode expect = testCase.get("expect");
            resetWorld(input);
            Instant now = instant(input, "now");
            clock.set(now);
            if (input.has("rateLimitedMs")) {
                // Ten attempts (the burst) made earlier leave exactly rateLimitedMs to wait now.
                long earlier = now.toEpochMilli() - (HttpShareRules.EXCHANGE_INTERVAL_MS - input.get("rateLimitedMs").asLong());
                for (int attempt = 0; attempt < HttpShareRules.EXCHANGE_BURST; attempt++) {
                    assertThat(runtime.exchangeLimiter().tryAcquire("127.0.0.1", earlier)).isZero();
                }
            }
            String contentType = input.path("contentType").asText("application/json");
            HttpResponse<String> response = withStore(input.path("readable").asBoolean(true),
                    () -> send("POST", "/api/public/http-shares/exchange", contentType,
                            JSON.writeValueAsString(input.get("body")), null, Map.of()));

            int status = expect.get("httpStatus").asInt();
            assertThat(response.statusCode()).as(response.body()).isEqualTo(status);
            assertThat(response.headers().firstValue("Cache-Control")).hasValue("no-store");
            if (status == 200) {
                assertThat(JSON.readTree(response.body())).isEqualTo(expect.get("body"));
                assertThat(response.headers().allValues("Set-Cookie"))
                        .containsExactly(setCookieString(expect.get("setCookie")));
                assertThat(response.headers().firstValue("Referrer-Policy")).hasValue("no-referrer");
            } else {
                assertThat(JSON.readTree(response.body()).get("code").asText()).isEqualTo(expect.get("code").asText());
                assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
            }
            if (expect.has("retryAfterSeconds")) {
                assertThat(response.headers().firstValue("Retry-After"))
                        .hasValue(expect.get("retryAfterSeconds").asText());
            }
            assertRevoke(input, expect, now);
            assertAudit(expect.get("audit"), Map.of());
        }));
    }

    // =============================================================================================
    // access (the real share entry and WebSocket handshake, a fake device)

    @TestFactory
    Stream<DynamicTest> access() {
        return cases("access").map(testCase -> DynamicTest.dynamicTest(testCase.get("name").asText(), () -> {
            JsonNode input = testCase.get("input");
            JsonNode expect = testCase.get("expect");
            JsonNode request = input.get("request");
            resetWorld(input);
            Instant now = instant(input, "now");
            clock.set(now);
            String shareId = request.get("path").asText().substring(HttpShareRules.SHARE_ROOT.length()).split("/")[0];
            List<HttpShareStreamRegistry.InFlight> held = new ArrayList<>();
            String admission = input.path("admission").asText("admitted");
            if (admission.equals("share-busy")) {
                long expiresAt = shareRepository.findById(shareId).orElseThrow().getExpiresAt();
                for (int stream = 0; stream < HttpShareRules.MAX_CONCURRENT_PER_SHARE; stream++) {
                    held.add(streamRegistry.tryAcquire(shareId, expiresAt));
                }
                assertThat(held).doesNotContainNull();
            } else if (admission.equals("rate-limited")) {
                for (int hit = 0; hit < HttpShareRules.SHARE_BURST; hit++) {
                    assertThat(runtime.shareLimiter().tryAcquire(shareId, now.toEpochMilli())).isZero();
                }
            }
            String clientName = CLIENT_PREFIX + 7;
            try (FakeShareDevice device = new FakeShareDevice(clientName, webSocketHandler, webSocketRegistry)) {
                RawCookieResponse response = withStore(input.path("readable").asBoolean(true),
                        () -> visit(request));
                List<Map<String, Object>> opens = device.opens();
                Object expectedStatus = expect.get("httpStatus").isTextual()
                        ? expect.get("httpStatus").asText() : expect.get("httpStatus").asInt();
                if ("forwarded".equals(expectedStatus)) {
                    assertForwarded(expect.get("forward"), request, opens, response);
                } else {
                    assertThat(response.getStatus()).isEqualTo(expect.get("httpStatus").asInt());
                    assertThat(opens).as("a refused request never reaches the device").isEmpty();
                    assertRefusal(expect, response);
                }
            } finally {
                held.forEach(HttpShareStreamRegistry.InFlight::release);
            }
            assertRevoke(input, expect, now);
            assertAudit(expect.get("audit"), Map.of());
        }));
    }

    private RawCookieResponse visit(JsonNode request) throws Exception {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest(
                request.get("method").asText(), request.get("path").asText());
        String rawQuery = request.path("rawQuery").asText("");
        if (!rawQuery.isEmpty()) {
            servletRequest.setQueryString(rawQuery);
        }
        for (JsonNode cookie : request.path("cookies")) {
            servletRequest.addHeader("Cookie", cookie.asText());
        }
        if (request.has("authorization")) {
            servletRequest.addHeader("Authorization", request.get("authorization").asText());
        }
        servletRequest.setRemoteAddr("203.0.113.9");
        RawCookieResponse response = new RawCookieResponse();
        if (!request.path("upgrade").asBoolean(false)) {
            shareController.handle(servletRequest, response);
            return response;
        }
        // A WebSocket upgrade: the handshake interceptor decides, the tunnel handler opens the stream.
        servletRequest.addHeader("Connection", "Upgrade");
        servletRequest.addHeader("Upgrade", "websocket");
        ServletServerHttpResponse handshakeResponse = new ServletServerHttpResponse(response);
        Map<String, Object> attributes = new HashMap<>();
        boolean admitted = shareHandshake.beforeHandshake(
                new ServletServerHttpRequest(servletRequest), handshakeResponse, webSocketHandler, attributes);
        if (!admitted) {
            handshakeResponse.close();
            return response;
        }
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.getAttributes()).thenReturn(attributes);
        when(session.isOpen()).thenReturn(true);
        webSocketHandler.afterConnectionEstablished(session);
        webSocketHandler.afterConnectionClosed(session, CloseStatus.NORMAL);
        response.setStatus(101);
        return response;
    }

    private void assertForwarded(JsonNode forward, JsonNode request, List<Map<String, Object>> opens,
                                 MockHttpServletResponse response) throws IOException {
        assertThat(opens).hasSize(1);
        Map<String, Object> open = opens.getFirst();
        boolean upgrade = request.path("upgrade").asBoolean(false);
        assertThat(open.get("source")).isEqualTo(upgrade ? "ws" : "http");
        assertThat(response.getStatus()).isEqualTo(upgrade ? 101 : 200);
        assertThat(open.get("route")).isEqualTo(forward.get("route").asText());
        if (!upgrade) {
            assertThat(open.get("method")).isEqualTo(forward.get("method").asText());
        }
        assertThat(open.get("relativePath")).isEqualTo(forward.get("relativePath").asText());
        assertThat(open.get("rawQuery") == null ? "" : open.get("rawQuery")).isEqualTo(forward.get("rawQuery").asText());
        @SuppressWarnings("unchecked")
        List<String> headers = (List<String>) open.get("headers");
        List<String> cookies = headers.stream()
                .filter(header -> header.regionMatches(true, 0, "Cookie:", 0, 7))
                .map(header -> header.substring(7))
                .toList();
        if (forward.get("cookie").isNull()) {
            assertThat(cookies).isEmpty();
        } else {
            assertThat(cookies).containsExactly(forward.get("cookie").asText());
        }
        // The token never reaches the device: not in the path, the query or any header.
        String token = VECTOR.get("token").get("examples").get(0).get("token").asText();
        assertThat(JSON.writeValueAsString(open)).doesNotContain(token);
    }

    private void assertRefusal(JsonNode expect, RawCookieResponse response) throws IOException {
        int status = expect.get("httpStatus").asInt();
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        if (status == 308) {
            assertThat(response.getHeader("Location")).isEqualTo(expect.get("location").asText());
            assertThat(response.getContentAsByteArray()).isEmpty();
            return;
        }
        assertThat(JSON.readTree(response.getContentAsString(StandardCharsets.UTF_8)).get("code").asText())
                .isEqualTo(expect.get("code").asText());
        if (expect.has("allow")) {
            assertThat(response.getHeader("Allow")).isEqualTo(expect.get("allow").asText());
        }
        if (expect.has("retryAfterSeconds")) {
            assertThat(response.getHeader("Retry-After")).isEqualTo(expect.get("retryAfterSeconds").asText());
        }
        if (expect.has("setCookie")) {
            assertThat(response.rawSetCookies).containsExactly(setCookieString(expect.get("setCookie")));
        } else {
            assertThat(response.rawSetCookies).isEmpty();
        }
    }

    // =============================================================================================
    // headers

    @TestFactory
    Stream<DynamicTest> requestCookieHeaders() {
        List<DynamicTest> tests = new ArrayList<>();
        int index = 0;
        for (JsonNode vector : VECTOR.get("headers").get("requestCookie")) {
            tests.add(DynamicTest.dynamicTest("requestCookie #" + index++, () -> {
                List<String> cookieHeaders = texts(vector.get("cookieHeaders"));
                String expected = textOrNull(vector.get("forwardedCookie"));
                assertThat(HttpShareRules.forwardedCookie(cookieHeaders)).isEqualTo(expected);
                // The same through the request-header rewriting the share entry applies.
                List<String> headers = new ArrayList<>(List.of("Accept:*/*"));
                cookieHeaders.forEach(value -> headers.add("Cookie:" + value));
                List<String> forwarded = HttpSpecusController.withoutShareCookie(headers);
                assertThat(forwarded).isEqualTo(expected == null
                        ? List.of("Accept:*/*") : List.of("Accept:*/*", "Cookie:" + expected));
            }));
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> responseHeaders() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode vector : VECTOR.get("headers").get("response")) {
            tests.add(DynamicTest.dynamicTest(vector.get("name").asText(), () ->
                    assertThat(HttpShareRules.responseHeaders(vector.get("status").asInt(),
                            texts(vector.get("upstream")), vector.get("shareId").asText()))
                            .isEqualTo(texts(vector.get("relayed")))));
        }
        return tests.stream();
    }

    // =============================================================================================
    // lifecycle (real management code paths)

    @TestFactory
    Stream<DynamicTest> lifecycle() {
        return cases("lifecycle").map(testCase -> DynamicTest.dynamicTest(testCase.get("name").asText(), () -> {
            JsonNode input = testCase.get("input");
            JsonNode expect = testCase.get("expect");
            resetWorld(input);
            Map<Long, Long> routeIds = new HashMap<>();
            List<JsonNode> responses = new ArrayList<>();
            Instant last = DEFAULT_NOW;
            for (JsonNode event : input.get("events")) {
                last = Instant.parse(event.get("at").asText());
                clock.set(last);
                JsonNode response = apply(event, routeIds);
                if (response != null) {
                    responses.add(response);
                }
            }
            assertThat(responses).isEqualTo(expect.has("responses") ? list(expect.get("responses")) : List.of());
            Map<Long, Long> expectedToActual = new HashMap<>(routeIds);
            assertAudit(expect.get("audit"), expectedToActual);
            long lastSecond = last.getEpochSecond();
            Map<String, JsonNode> finalStates = new HashMap<>();
            expect.get("shares").properties().forEach(entry -> finalStates.put(entry.getKey(), entry.getValue()));
            assertThat(shareRepository.findAll()).hasSize(finalStates.size());
            for (Map.Entry<String, JsonNode> entry : finalStates.entrySet()) {
                HttpShare share = shareRepository.findById(entry.getKey()).orElseThrow();
                String status = share.getRevokedAt() != null ? "revoked"
                        : share.getExpiresAt() <= lastSecond ? "expired" : "active";
                assertThat(status).as(entry.getKey()).isEqualTo(entry.getValue().get("status").asText());
                assertThat(share.getRevokeReason()).as(entry.getKey())
                        .isEqualTo(textOrNull(entry.getValue().get("revokeReason")));
                assertThat(share.getRevokedBy()).as(entry.getKey())
                        .isEqualTo(textOrNull(entry.getValue().get("revokedBy")));
            }
        }));
    }

    private JsonNode apply(JsonNode event, Map<Long, Long> routeIds) throws Exception {
        String kind = event.get("kind").asText();
        String actor = textOrNull(event.get("actor"));
        switch (kind) {
            case "revoke" -> {
                long routeId = event.get("routeId").asLong();
                HttpResponse<String> response = send("POST", "/api/admin/http-routes/" + routeId + "/shares/"
                        + event.get("shareId").asText() + "/revoke", "application/json", "{}", bearer(actor), Map.of());
                JsonNode body = JSON.readTree(response.body());
                Map<String, Object> summary = new java.util.LinkedHashMap<>();
                summary.put("httpStatus", response.statusCode());
                if (response.statusCode() == 200) {
                    summary.put("status", body.get("share").get("status").asText());
                } else {
                    summary.put("code", body.get("code").asText());
                }
                return JSON.valueToTree(summary);
            }
            case "route-created" -> {
                JsonNode route = event.get("route");
                boolean auth = route.get("authEnabled").asBoolean();
                var view = routeService.createRoute(context(actor), route.get("clientId").asLong(),
                        new HttpRouteService.RouteMutation(route.get("name").asText(), "http://127.0.0.1:9000",
                                route.get("enabled").asBoolean(), null, null, null, null, auth,
                                auth ? "basic-" + route.get("name").asText() : null, auth ? "first-secret" : null));
                routeIds.put(route.get("routeId").asLong(), view.id());
            }
            case "route-updated" -> {
                long routeId = routeIds.getOrDefault(event.get("routeId").asLong(), event.get("routeId").asLong());
                HttpRouteMapping current = routeRepository.findById(routeId).orElseThrow();
                Boolean auth = event.has("authEnabled") ? event.get("authEnabled").asBoolean() : null;
                boolean credentialsChanged = event.path("credentialsChanged").asBoolean(false);
                String username = Boolean.TRUE.equals(auth) && current.getAuthUsername() == null
                        ? "basic-" + current.getRoute() : null;
                routeService.updateRoute(context(actor), routeId, new HttpRouteService.RouteMutation(
                        current.getRoute(), current.getTargetBaseUrl(),
                        event.has("enabled") ? event.get("enabled").asBoolean() : null,
                        null, null, null, null, auth, username, credentialsChanged ? "rotated-secret" : null));
            }
            case "route-deleted" -> routeService.deleteRoute(context(actor),
                    routeIds.getOrDefault(event.get("routeId").asLong(), event.get("routeId").asLong()));
            case "client-disabled" -> clientService.updateClient(context(actor), event.get("clientId").asLong(),
                    new ClientAccountService.ClientMutation(null, false, null));
            case "client-deleted" -> clientService.deleteClient(context(actor), event.get("clientId").asLong());
            case "user-updated" -> userService.updateUser(context(actor), event.get("username").asText(),
                    new ManagementUserService.UserMutation(null, null,
                            event.has("role") ? ManagementRole.valueOf(event.get("role").asText()) : null,
                            event.has("enabled") ? event.get("enabled").asBoolean() : null));
            case "user-deleted" -> userService.deleteUser(context(actor), event.get("username").asText());
            case "sweep" -> shareService.sweep();
            case "silent-change" -> {
                // A change that bypasses every hook: a direct write to the route row.
                assertThat(event.get("table").asText()).isEqualTo("routes");
                HttpRouteMapping route = routeRepository.findById(event.get("key").asLong()).orElseThrow();
                JsonNode set = event.get("set");
                if (set.has("enabled")) {
                    route.setEnabled(set.get("enabled").asBoolean());
                }
                if (set.has("authEnabled")) {
                    route.setAuthEnabled(set.get("authEnabled").asBoolean());
                }
                routeRepository.saveAndFlush(route);
            }
            default -> throw new AssertionError("unknown event " + kind);
        }
        return null;
    }

    // =============================================================================================
    // rate (the server's own limiter instances)

    @TestFactory
    Stream<DynamicTest> rate() {
        List<DynamicTest> tests = new ArrayList<>();
        for (String name : List.of("exchange", "share")) {
            JsonNode section = VECTOR.get("rate").get(name);
            tests.add(DynamicTest.dynamicTest(name, () -> {
                GcraRateLimiter limiter = name.equals("exchange") ? runtime.exchangeLimiter() : runtime.shareLimiter();
                limiter.clear();
                for (JsonNode event : section.get("events")) {
                    int admitted = 0;
                    Long retryAfter = null;
                    for (int request = 0; request < event.get("requests").asInt(); request++) {
                        long waitMs = limiter.tryAcquire(event.get("key").asText(), event.get("atMs").asLong());
                        if (waitMs == 0) {
                            admitted++;
                        } else if (retryAfter == null) {
                            retryAfter = GcraRateLimiter.retryAfterSeconds(waitMs);
                        }
                    }
                    assertThat(admitted).as(event.toString()).isEqualTo(event.get("admitted").asInt());
                    assertThat(retryAfter).as(event.toString()).isEqualTo(
                            event.has("retryAfterSeconds") ? event.get("retryAfterSeconds").asLong() : null);
                }
            }));
        }
        return tests.stream();
    }

    // =============================================================================================
    // The fixture world

    private void resetWorld(JsonNode input) {
        shareRepository.deleteAllInBatch();
        auditRepository.deleteAllInBatch();
        routeRepository.deleteAllInBatch();
        clientRepository.deleteAllInBatch();
        userRepository.deleteAllInBatch();
        runtime.exchangeLimiter().clear();
        runtime.shareLimiter().clear();
        runtime.useRandom(null);
        streamRegistry.clear();
        clock.set(DEFAULT_NOW);
        String stamp = DEFAULT_NOW.toString();
        JsonNode world = VECTOR.get("world");
        world.get("users").forEach(node -> {
            ManagementUser user = new ManagementUser();
            String name = node.get("username").asText();
            user.setUsername("account-" + name);
            user.setLoginName(name);
            user.setLoginNameNormalized(name.toLowerCase(java.util.Locale.ROOT));
            user.setTenantId(node.get("tenantId").asText());
            user.setPasswordHash("0".repeat(64));
            user.setRole(ManagementRole.valueOf(node.get("role").asText()));
            user.setEnabled(node.get("enabled").asBoolean());
            user.setCreatedAt(stamp);
            user.setUpdatedAt(stamp);
            userRepository.save(user);
        });
        world.get("clients").forEach(node -> {
            ClientAccount client = new ClientAccount();
            client.setId(node.get("clientId").asLong());
            client.setTenantId(node.get("tenantId").asText());
            client.setOwnerUsername(node.get("owner").asText());
            client.setClientName(CLIENT_PREFIX + node.get("clientId").asLong());
            client.setPasswordHash("0".repeat(64));
            client.setEnabled(node.get("enabled").asBoolean());
            client.setCreatedAt(stamp);
            client.setUpdatedAt(stamp);
            clientRepository.save(client);
        });
        world.get("routes").forEach(node -> {
            HttpRouteMapping route = new HttpRouteMapping();
            route.setId(node.get("routeId").asLong());
            route.setTenantId(node.get("tenantId").asText());
            route.setClientId(node.get("clientId").asLong());
            route.setClientName(CLIENT_PREFIX + node.get("clientId").asLong());
            route.setRoute(node.get("name").asText());
            route.setTargetBaseUrl("http://127.0.0.1:8080");
            route.setEnabled(node.get("enabled").asBoolean());
            boolean auth = node.get("authEnabled").asBoolean();
            route.setAuthEnabled(auth);
            route.setAuthUsername(auth ? "basic-" + node.get("name").asText() : null);
            route.setAuthPasswordHash(auth ? "1".repeat(64) : null);
            route.setCreatedAt(stamp);
            route.setUpdatedAt(stamp);
            routeRepository.save(route);
        });
        for (JsonNode change : input.path("worldChanges")) {
            applyWorldChange(change);
        }
        for (JsonNode node : input.path("shares")) {
            HttpShare share = new HttpShare();
            share.setShareId(node.get("shareId").asText());
            share.setTenantId(node.get("tenantId").asText());
            share.setRouteId(node.get("routeId").asLong());
            share.setTokenSha256(node.get("tokenSha256").asText());
            share.setAccess(node.get("access").asText());
            share.setPathPrefix(node.get("pathPrefix").asText());
            share.setLabel(textOrNull(node.get("label")));
            share.setCreatedBy(node.get("createdBy").asText());
            share.setCreatedAt(Instant.parse(node.get("createdAt").asText()).getEpochSecond());
            share.setExpiresAt(Instant.parse(node.get("expiresAt").asText()).getEpochSecond());
            share.setRevokedAt(node.get("revokedAt").isNull() ? null : Instant.parse(node.get("revokedAt").asText()).getEpochSecond());
            share.setRevokedBy(textOrNull(node.get("revokedBy")));
            share.setRevokeReason(textOrNull(node.get("revokeReason")));
            shareRepository.save(share);
        }
    }

    private void applyWorldChange(JsonNode change) {
        String table = change.get("table").asText();
        boolean deleted = change.path("deleted").asBoolean(false);
        JsonNode set = change.path("set");
        switch (table) {
            case "users" -> {
                ManagementUser user = userRepository.findById("account-" + change.get("key").asText()).orElseThrow();
                if (deleted) {
                    userRepository.delete(user);
                    return;
                }
                if (set.has("enabled")) {
                    user.setEnabled(set.get("enabled").asBoolean());
                }
                if (set.has("role")) {
                    user.setRole(ManagementRole.valueOf(set.get("role").asText()));
                }
                userRepository.save(user);
            }
            case "clients" -> {
                ClientAccount client = clientRepository.findById(change.get("key").asLong()).orElseThrow();
                if (deleted) {
                    clientRepository.delete(client);
                    return;
                }
                if (set.has("enabled")) {
                    client.setEnabled(set.get("enabled").asBoolean());
                }
                clientRepository.save(client);
            }
            case "routes" -> {
                HttpRouteMapping route = routeRepository.findById(change.get("key").asLong()).orElseThrow();
                if (deleted) {
                    routeRepository.delete(route);
                    return;
                }
                if (set.has("enabled")) {
                    route.setEnabled(set.get("enabled").asBoolean());
                }
                if (set.has("authEnabled")) {
                    route.setAuthEnabled(set.get("authEnabled").asBoolean());
                }
                routeRepository.save(route);
            }
            default -> throw new AssertionError("unknown table " + table);
        }
    }

    // =============================================================================================
    // Assertions and helpers

    /** The share row carries the read-time revocation (system actor) exactly when the vector says so. */
    private void assertRevoke(JsonNode input, JsonNode expect, Instant now) {
        for (JsonNode node : input.path("shares")) {
            HttpShare share = shareRepository.findById(node.get("shareId").asText()).orElseThrow();
            if (expect.has("revoke")) {
                assertThat(share.getRevokedAt()).isEqualTo(now.getEpochSecond());
                assertThat(share.getRevokedBy()).isNull();
                assertThat(share.getRevokeReason()).isEqualTo(expect.get("revoke").get("reason").asText());
            } else {
                assertThat(share.getRevokeReason()).isEqualTo(textOrNull(node.get("revokeReason")));
                assertThat(share.getRevokedBy()).isEqualTo(textOrNull(node.get("revokedBy")));
            }
        }
    }

    private void assertAudit(JsonNode expected, Map<Long, Long> routeIds) throws IOException {
        List<HttpAccessAudit> rows = auditRepository.findAllByOrderByIdAsc();
        List<JsonNode> entries = expected == null ? List.of() : list(expected);
        assertThat(rows).as("audit entries").hasSize(entries.size());
        for (int index = 0; index < rows.size(); index++) {
            HttpAccessAudit row = rows.get(index);
            JsonNode entry = entries.get(index);
            String label = "audit #" + index + " " + entry;
            assertThat(row.getAction()).as(label).isEqualTo(entry.get("action").asText());
            assertThat(HttpShareService.stamp(row.getOccurredAt())).as(label).isEqualTo(entry.get("at").asText());
            assertThat(row.getActor()).as(label).isEqualTo(textOrNull(entry.get("actor")));
            long expectedRoute = entry.get("routeId").asLong();
            assertThat(row.getRouteId()).as(label).isEqualTo(routeIds.getOrDefault(expectedRoute, expectedRoute));
            assertThat(row.getShareId()).as(label).isEqualTo(textOrNull(entry.get("shareId")));
            assertThat(JSON.readTree(row.getDetailJson())).as(label).isEqualTo(entry.get("detail"));
            assertThat(row.getTenantId()).as(label).isEqualTo("t1");
        }
    }

    private static String setCookieString(JsonNode cookie) {
        assertThat(cookie.get("domain").isNull()).isTrue();
        assertThat(cookie.get("httpOnly").asBoolean()).isTrue();
        assertThat(cookie.get("secure").asBoolean()).isTrue();
        return cookie.get("name").asText() + "=" + cookie.get("value").asText()
                + "; Path=" + cookie.get("path").asText()
                + "; Max-Age=" + cookie.get("maxAge").asLong()
                + "; HttpOnly; Secure; SameSite=" + cookie.get("sameSite").asText();
    }

    private ManagementContext context(String actor) {
        JsonNode user = VECTOR.get("world").get("users").get(actor);
        return new ManagementContext(new TenantContext(user.get("tenantId").asText()), actor,
                "ADMIN".equals(user.get("role").asText()));
    }

    private String bearer(String username) {
        JsonNode user = VECTOR.get("world").get("users").get(username);
        return tokens.issueToken(username, user.get("tenantId").asText(),
                ManagementRole.valueOf(user.get("role").asText()));
    }

    private HttpResponse<String> send(String method, String path, String contentType, String body, String bearer,
                                      Map<String, String> headers) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        if (contentType != null) {
            builder.header("Content-Type", contentType);
        }
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        headers.forEach(builder::header);
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    /** Runs {@code action} with the share table unreadable when {@code readable} is false. */
    private <T> T withStore(boolean readable, ThrowingSupplier<T> action) throws Exception {
        if (readable) {
            return action.get();
        }
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("ALTER TABLE http_share RENAME TO http_share_offline");
        try {
            return action.get();
        } finally {
            jdbc.execute("ALTER TABLE http_share_offline RENAME TO http_share");
        }
    }

    @FunctionalInterface
    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    private static HttpShareRandom bytesFrom(String... hexChunks) {
        Deque<byte[]> chunks = new ArrayDeque<>();
        for (String hex : hexChunks) {
            chunks.add(HexFormat.of().parseHex(hex));
        }
        return bytes -> {
            byte[] next = chunks.poll();
            assertThat(next).as("injected random bytes").isNotNull().hasSize(bytes.length);
            System.arraycopy(next, 0, bytes, 0, bytes.length);
        };
    }

    private static Stream<JsonNode> cases(String section) {
        return list(VECTOR.get(section)).stream();
    }

    private static Instant instant(JsonNode input, String field) {
        return input.has(field) ? Instant.parse(input.get(field).asText()) : DEFAULT_NOW;
    }

    private static List<JsonNode> list(JsonNode array) {
        List<JsonNode> values = new ArrayList<>();
        array.forEach(values::add);
        return values;
    }

    private static List<String> texts(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(node -> values.add(node.asText()));
        return values;
    }

    private static String textOrNull(JsonNode node) {
        return node == null || node.isNull() ? null : node.asText();
    }

    private static JsonNode readVector() {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/temporary-http-share-v1.json");
            if (Files.isRegularFile(candidate)) {
                try {
                    return JSON.readTree(Files.readString(candidate, StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        throw new IllegalStateException("cannot locate temporary-http-share-v1.json");
    }

    /**
     * Keeps the Set-Cookie values exactly as the server wrote them; the mock response would
     * otherwise re-serialise them through its cookie parser (adding an Expires attribute).
     */
    static final class RawCookieResponse extends MockHttpServletResponse {
        final List<String> rawSetCookies = new ArrayList<>();

        @Override
        public void addHeader(String name, String value) {
            if ("Set-Cookie".equalsIgnoreCase(name)) {
                rawSetCookies.add(value);
            }
            super.addHeader(name, value);
        }

        @Override
        public void setHeader(String name, String value) {
            if ("Set-Cookie".equalsIgnoreCase(name)) {
                rawSetCookies.clear();
                rawSetCookies.add(value);
            }
            super.setHeader(name, value);
        }
    }

    /** A clock the vector moves between events. */
    static final class MutableClock extends Clock {
        private volatile Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void set(Instant next) {
            this.instant = next;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
