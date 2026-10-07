package com.theshuai.specusserver.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusserver.httpshare.HttpShareRules;
import com.theshuai.specusserver.httpshare.HttpShareStreamRegistry;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpShare;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.HttpShareRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.security.LocalTokenService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Temporary HTTP shares over real HTTP against the running server: the exchange cookie, a request
 * relayed to a fake device without the share cookie, the share response rules, revocation, a
 * revocation by another instance cutting an in-flight response, and the cascades from the route,
 * client and user management endpoints. Background sweep and stream recheck run as in production.
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
                "specus.auth.password=root-operator-password"
        }
)
class HttpShareHttpTests {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String TENANT = "t1";
    private static final String ADMIN = "share-admin";

    @Value("${local.server.port}")
    private int port;

    @Autowired private ManagementUserRepository userRepository;
    @Autowired private ClientAccountRepository clientRepository;
    @Autowired private HttpRouteMappingRepository routeRepository;
    @Autowired private HttpShareRepository shareRepository;
    @Autowired private HttpShareStreamRegistry streamRegistry;
    @Autowired private WebSocketSpecusHandler webSocketHandler;
    @Autowired private WebSocketStreamRegistry webSocketRegistry;
    @Autowired private LocalTokenService tokens;
    @Autowired private DataSource dataSource;

    private final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private final List<FakeShareDevice> devices = new ArrayList<>();

    @AfterEach
    void unplugDevices() {
        devices.forEach(FakeShareDevice::close);
        devices.clear();
    }

    /**
     * The share, workbench and connectivity-check contracts make every answer private, Spring
     * Security's 401 included; other admin endpoints keep the portal's no-cache set.
     */
    @Test
    void refusalsBeforeAnyControllerArePrivateOnPrivateEndpoints() throws Exception {
        for (String[] call : new String[][] {
                {"POST", "/api/admin/http-routes/1/shares"},
                {"GET", "/api/admin/http-routes/1/shares"},
                {"GET", "/api/admin/http-routes/1/shares/abc"},
                {"POST", "/api/admin/http-routes/1/shares/abc/revoke"},
                {"GET", "/api/admin/http-routes/1/access-audit"},
                {"GET", "/api/admin/http-access-audit"},
                {"GET", "/api/admin/workbench"},
                {"POST", "/api/admin/http-routes/1/connectivity-check"}}) {
            for (String bearer : new String[] {null, "not-a-token"}) {
                HttpResponse<String> refused = send(call[0], call[1], call[0].equals("POST") ? "{}" : null, bearer);
                assertThat(refused.statusCode()).as("%s %s", call[0], call[1]).isEqualTo(401);
                assertThat(refused.headers().allValues("Cache-Control")).as("%s %s", call[0], call[1])
                        .containsExactly("private, no-store");
            }
        }
        HttpResponse<String> other = send("GET", "/api/admin/clients", null, null);
        assertThat(other.statusCode()).isEqualTo(401);
        assertThat(other.headers().firstValue("Cache-Control"))
                .hasValue("no-cache, no-store, max-age=0, must-revalidate");
    }

    @Test
    void exchangeSetsOnlyTheScopedHttpOnlyCookie() throws Exception {
        Fixture fixture = fixture("exchange");
        Share share = fixture.share("{\"expiresInSeconds\":3600,\"pathPrefix\":\"/docs\"}");

        HttpResponse<String> exchanged = exchange(share.token(), "application/json");

        assertThat(exchanged.statusCode()).as(exchanged.body()).isEqualTo(200);
        assertThat(exchanged.headers().allValues("Set-Cookie")).singleElement().satisfies(cookie -> assertThat(cookie)
                .matches("__Secure-specus_http_share=" + share.token().replace(".", "\\.")
                        + "; Path=/http-share/" + share.shareId() + "/; Max-Age=(3599|3600)"
                        + "; HttpOnly; Secure; SameSite=Strict"));
        assertThat(exchanged.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(exchanged.headers().firstValue("Referrer-Policy")).hasValue("no-referrer");
        JsonNode body = JSON.readTree(exchanged.body());
        assertThat(body.get("location").asText()).isEqualTo("/http-share/" + share.shareId() + "/docs/");
        assertThat(body.has("token")).isFalse();
        assertThat(exchanged.body()).doesNotContain(share.token());

        HttpResponse<String> form = exchange(share.token(), "application/x-www-form-urlencoded");
        assertThat(form.statusCode()).isEqualTo(415);
        assertThat(form.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(JSON.readTree(form.body()).get("code").asText()).isEqualTo("SHARE_REQUEST_INVALID");
    }

    @Test
    void relayStripsOnlyTheShareCookieAndConfinesTheResponse() throws Exception {
        Fixture fixture = fixture("relay");
        fixture.device().respondWith(new FakeShareDevice.Response(200, List.of(
                "Content-Type:text/plain",
                "Set-Cookie:sid=1; Path=/; Domain=example.com; HttpOnly",
                "Set-Cookie:__Host-csrf=x; Path=/; Secure",
                "Cache-Control:public, max-age=60",
                "Expires:Wed, 21 Oct 2026 07:28:00 GMT",
                "Clear-Site-Data:\"cookies\""), "hello", true));
        Share share = fixture.share("{\"expiresInSeconds\":3600}");

        HttpResponse<String> response = visit(share, "/docs/page?x=1", Map.of(
                "Cookie", "theme=dark; " + HttpShareRules.COOKIE_NAME + "=" + share.token() + "; sid=abc",
                "Authorization", "Bearer upstream-token"));

        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("hello");
        assertThat(response.headers().allValues("Set-Cookie"))
                .containsExactly("sid=1; Path=/http-share/" + share.shareId() + "/; HttpOnly");
        assertThat(response.headers().allValues("Cache-Control")).containsExactly("private, no-cache");
        assertThat(response.headers().map().keySet().stream().map(name -> name.toLowerCase(Locale.ROOT)))
                .doesNotContain("clear-site-data", "expires", "content-security-policy", "x-frame-options",
                        "referrer-policy");

        Map<String, Object> open = fixture.device().opens().getFirst();
        assertThat(open.get("route")).isEqualTo("app");
        assertThat(open.get("method")).isEqualTo("GET");
        assertThat(open.get("relativePath")).isEqualTo("/docs/page");
        assertThat(open.get("rawQuery")).isEqualTo("x=1");
        @SuppressWarnings("unchecked")
        List<String> headers = (List<String>) open.get("headers");
        assertThat(headers.stream().filter(header -> header.regionMatches(true, 0, "Cookie:", 0, 7)))
                .containsExactly("Cookie:theme=dark; sid=abc");
        assertThat(headers).anySatisfy(header -> assertThat(header.toLowerCase(Locale.ROOT))
                .isEqualTo("authorization:bearer upstream-token"));
        assertThat(String.join("\n", headers)).doesNotContain(share.token());
    }

    @Test
    void revocationAnswersGoneAndClearsTheCookie() throws Exception {
        Fixture fixture = fixture("revoke");
        Share share = fixture.share("{\"expiresInSeconds\":3600}");
        Map<String, String> cookie = Map.of("Cookie", HttpShareRules.COOKIE_NAME + "=" + share.token());
        assertThat(visit(share, "/", cookie).statusCode()).isEqualTo(200);

        HttpResponse<String> revoked = send("POST", "/api/admin/http-routes/" + fixture.routeId() + "/shares/"
                + share.shareId() + "/revoke", null, fixture.ownerToken());
        assertThat(revoked.statusCode()).as(revoked.body()).isEqualTo(200);
        assertThat(JSON.readTree(revoked.body()).get("share").get("status").asText()).isEqualTo("revoked");

        HttpResponse<String> gone = visit(share, "/", cookie);
        assertThat(gone.statusCode()).isEqualTo(410);
        assertThat(JSON.readTree(gone.body()).get("code").asText()).isEqualTo("SHARE_REVOKED");
        assertThat(gone.headers().allValues("Set-Cookie")).containsExactly(HttpShareRules.COOKIE_NAME
                + "=; Path=/http-share/" + share.shareId() + "/; Max-Age=0; HttpOnly; Secure; SameSite=Strict");
        assertThat(gone.headers().firstValue("Cache-Control")).hasValue("no-store");
        assertThat(fixture.device().opens()).hasSize(1);

        HttpResponse<String> audit = send("GET", "/api/admin/http-routes/" + fixture.routeId() + "/access-audit",
                null, fixture.ownerToken());
        assertThat(audit.statusCode()).as(audit.body()).isEqualTo(200);
        JsonNode entries = JSON.readTree(audit.body()).get("entries");
        assertThat(entries).hasSize(3);
        assertThat(entries.get(0).get("action").asText()).isEqualTo("share.revoked");
        assertThat(entries.get(0).get("actor").asText()).isEqualTo(fixture.owner());
        assertThat(entries.get(0).get("detail").get("reason").asText()).isEqualTo("revoked-by-user");
        assertThat(entries.get(1).get("action").asText()).isEqualTo("share.created");
        assertThat(entries.get(2).get("action").asText()).isEqualTo("route.created");
        assertThat(entries.get(2).get("detail").get("exposure").asText()).isEqualTo("protected");
    }

    @Test
    void revocationOnAnotherInstanceCutsAnInFlightResponseWithinFiveSeconds() throws Exception {
        Fixture fixture = fixture("inflight");
        fixture.device().respondWith(new FakeShareDevice.Response(
                200, List.of("Content-Type:text/plain"), "first-chunk", false));
        Share share = fixture.share("{\"expiresInSeconds\":3600}");
        HttpRequest request = HttpRequest.newBuilder(uri(share.sharePath() + "stream"))
                .header("Cookie", HttpShareRules.COOKIE_NAME + "=" + share.token())
                .GET().build();
        HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        assertThat(response.statusCode()).isEqualTo(200);
        InputStream body = response.body();
        assertThat(new String(body.readNBytes("first-chunk".length()), StandardCharsets.UTF_8)).isEqualTo("first-chunk");
        assertThat(streamRegistry.count(share.shareId())).isEqualTo(1);

        // Another instance revokes the share: only the shared database changes.
        new JdbcTemplate(dataSource).update(
                "UPDATE http_share SET revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE share_id = ?",
                Instant.now().getEpochSecond(), "someone-elsewhere", "revoked-by-user", share.shareId());
        long started = System.nanoTime();
        CompletableFuture<byte[]> rest = CompletableFuture.supplyAsync(() -> {
            try {
                return body.readAllBytes();
            } catch (IOException aborted) {
                throw new IllegalStateException(aborted);
            }
        });
        Throwable outcome = null;
        try {
            rest.get(5, TimeUnit.SECONDS);
        } catch (java.util.concurrent.ExecutionException aborted) {
            outcome = aborted.getCause();
        }
        Duration elapsed = Duration.ofNanos(System.nanoTime() - started);
        assertThat(elapsed).isLessThan(Duration.ofSeconds(5));
        assertThat(outcome).as("the response is aborted, not completed").isNotNull();
        int streamId = fixture.device().written().stream()
                .filter(packet -> packet.getNatMessageType() == NatMessageType.OPEN)
                .mapToInt(NatMessagePacket::getStreamId).findFirst().orElseThrow();
        assertThat(fixture.device().sawReset(streamId)).as("the device got a NAT RST").isTrue();
        assertThat(streamRegistry.count(share.shareId())).isZero();
    }

    @Test
    void disablingTheRouteThroughTheApiEndsItsShares() throws Exception {
        Fixture fixture = fixture("route-disable");
        Share share = fixture.share("{\"expiresInSeconds\":3600}");

        HttpResponse<String> updated = send("PUT", "/api/admin/http-routes/" + fixture.routeId(),
                "{\"route\":\"app\",\"targetBaseUrl\":\"http://127.0.0.1:8080\",\"enabled\":false}",
                fixture.ownerToken());

        assertThat(updated.statusCode()).as(updated.body()).isEqualTo(200);
        assertRevoked(share, "route-disabled", fixture.owner());
        JsonNode entries = routeAudit(fixture);
        assertThat(actions(entries)).containsExactly(
                "share.revoked", "route.exposure-changed", "share.created", "route.created");
        assertThat(entries.get(1).get("detail")).isEqualTo(JSON.readTree("{\"from\":\"protected\",\"to\":\"disabled\"}"));
        HttpResponse<String> reenabled = send("PUT", "/api/admin/http-routes/" + fixture.routeId(),
                "{\"route\":\"app\",\"targetBaseUrl\":\"http://127.0.0.1:8080\",\"enabled\":true}",
                fixture.ownerToken());
        assertThat(reenabled.statusCode()).isEqualTo(200);
        assertRevoked(share, "route-disabled", fixture.owner());
    }

    @Test
    void disablingTheCreatorThroughTheApiEndsTheCreatorsShares() throws Exception {
        Fixture fixture = fixture("user-disable");
        Share share = fixture.share("{\"expiresInSeconds\":3600}");

        HttpResponse<String> disabled = send("PUT", "/api/admin/users/" + fixture.owner(),
                "{\"enabled\":false}", adminToken());

        assertThat(disabled.statusCode()).as(disabled.body()).isEqualTo(200);
        assertRevoked(share, "creator-lost-access", ADMIN);
        HttpResponse<String> enabled = send("PUT", "/api/admin/users/" + fixture.owner(),
                "{\"enabled\":true}", adminToken());
        assertThat(enabled.statusCode()).isEqualTo(200);
        assertRevoked(share, "creator-lost-access", ADMIN);
    }

    @Test
    void deletingTheClientThroughTheApiDeletesItsRoutesAndEndsTheirShares() throws Exception {
        Fixture fixture = fixture("client-delete");
        Share share = fixture.share("{\"expiresInSeconds\":3600}");

        HttpResponse<String> deleted = send("DELETE", "/api/admin/clients/" + fixture.clientId(), null, adminToken());

        assertThat(deleted.statusCode()).as(deleted.body()).isEqualTo(204);
        assertThat(routeRepository.findById(fixture.routeId())).isEmpty();
        assertRevoked(share, "client-deleted", ADMIN);
        HttpResponse<String> audit = send("GET", "/api/admin/http-access-audit?routeId=" + fixture.routeId(),
                null, adminToken());
        assertThat(audit.statusCode()).as(audit.body()).isEqualTo(200);
        JsonNode entries = JSON.readTree(audit.body()).get("entries");
        assertThat(actions(entries)).containsExactly("share.revoked", "route.deleted", "share.created", "route.created");
        assertThat(entries.get(1).get("detail")).isEqualTo(JSON.readTree("{\"exposure\":\"protected\"}"));
        assertThat(entries.get(1).get("actor").asText()).isEqualTo(ADMIN);
        HttpResponse<String> forbidden = send("GET", "/api/admin/http-access-audit", null, fixture.ownerToken());
        assertThat(forbidden.statusCode()).isEqualTo(403);
        assertThat(JSON.readTree(forbidden.body()).get("code").asText()).isEqualTo("SHARE_FORBIDDEN");
    }

    // ---------------------------------------------------------------------------------------------

    private record Share(String shareId, String token) {
        String sharePath() {
            return HttpShareRules.SHARE_ROOT + shareId + "/";
        }
    }

    private record Fixture(HttpShareHttpTests test, String owner, String ownerToken, long clientId, long routeId,
                           FakeShareDevice device) {
        Share share(String body) throws Exception {
            HttpResponse<String> created = test.send("POST", "/api/admin/http-routes/" + routeId + "/shares",
                    body, ownerToken);
            assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
            JsonNode json = JSON.readTree(created.body());
            return new Share(json.get("share").get("shareId").asText(), json.get("token").asText());
        }
    }

    /** A fresh owner, client (with a connected fake device) and protected route created over the API. */
    private Fixture fixture(String name) throws Exception {
        ensureUser(ADMIN, ManagementRole.ADMIN);
        String owner = "owner-" + name;
        ensureUser(owner, ManagementRole.USER);
        String ownerToken = tokens.issueToken(owner, TENANT, ManagementRole.USER);
        ClientAccount client = new ClientAccount();
        client.setId(System.nanoTime() % 1_000_000_000L + 1);
        client.setTenantId(TENANT);
        client.setOwnerUsername(owner);
        client.setClientName("share-http-" + name + "-" + System.nanoTime());
        client.setPasswordHash("0".repeat(64));
        client.setEnabled(true);
        client.setCreatedAt(Instant.now().toString());
        client.setUpdatedAt(Instant.now().toString());
        clientRepository.save(client);
        HttpResponse<String> route = send("POST", "/api/admin/clients/" + client.getId() + "/http-routes",
                "{\"route\":\"app\",\"targetBaseUrl\":\"http://127.0.0.1:8080\",\"enabled\":true,"
                        + "\"authEnabled\":true,\"authUsername\":\"basic\",\"authPassword\":\"basic-secret\"}",
                ownerToken);
        assertThat(route.statusCode()).as(route.body()).isEqualTo(201);
        FakeShareDevice device = new FakeShareDevice(client.getClientName(), webSocketHandler, webSocketRegistry);
        devices.add(device);
        return new Fixture(this, owner, ownerToken, client.getId(), JSON.readTree(route.body()).get("id").asLong(), device);
    }

    private void ensureUser(String name, ManagementRole role) {
        if (userRepository.findByTenantIdAndLoginNameNormalized(TENANT, name).isPresent()) {
            return;
        }
        ManagementUser user = new ManagementUser();
        user.setUsername("account-" + name);
        user.setLoginName(name);
        user.setLoginNameNormalized(name);
        user.setTenantId(TENANT);
        user.setPasswordHash("0".repeat(64));
        user.setRole(role);
        user.setEnabled(true);
        user.setCreatedAt(Instant.now().toString());
        user.setUpdatedAt(Instant.now().toString());
        userRepository.save(user);
    }

    private String adminToken() {
        return tokens.issueToken(ADMIN, TENANT, ManagementRole.ADMIN);
    }

    private void assertRevoked(Share share, String reason, String actor) {
        HttpShare stored = shareRepository.findById(share.shareId()).orElseThrow();
        assertThat(stored.getRevokedAt()).isNotNull();
        assertThat(stored.getRevokeReason()).isEqualTo(reason);
        assertThat(stored.getRevokedBy()).isEqualTo(actor);
    }

    private JsonNode routeAudit(Fixture fixture) throws Exception {
        HttpResponse<String> audit = send("GET", "/api/admin/http-routes/" + fixture.routeId() + "/access-audit",
                null, fixture.ownerToken());
        assertThat(audit.statusCode()).as(audit.body()).isEqualTo(200);
        return JSON.readTree(audit.body()).get("entries");
    }

    private static List<String> actions(JsonNode entries) {
        List<String> actions = new ArrayList<>();
        entries.forEach(entry -> actions.add(entry.get("action").asText()));
        return actions;
    }

    private HttpResponse<String> exchange(String token, String contentType) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(uri("/api/public/http-shares/exchange"))
                .header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"" + token + "\"}"))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> visit(Share share, String relative, Map<String, String> headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(
                uri(HttpShareRules.SHARE_ROOT + share.shareId() + relative)).GET();
        headers.forEach(builder::header);
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> send(String method, String path, String body, String bearer) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri(path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }
}
