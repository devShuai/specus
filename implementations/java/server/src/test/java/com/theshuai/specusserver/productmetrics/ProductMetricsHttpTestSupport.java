package com.theshuai.specusserver.productmetrics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.LocalTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;

import static org.mockito.Mockito.when;

/**
 * Shared fixture of the product metrics HTTP tests: the whole application on a random port
 * (security filter chain, token decoding, the shared ManagementContextResolver, the controllers and
 * the store) over an in-memory SQLite database, with the product metrics clock pinned by the test.
 * Accounts are created through ManagementUserService and bearer tokens are minted the way
 * /auth/login mints them.
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
                // The tests run the retention sweep themselves, at the pinned time.
                "specus.product-metrics.sweep-initial-delay-ms=86400000"
        })
abstract class ProductMetricsHttpTestSupport {
    static final ObjectMapper JSON = new ObjectMapper();
    static final String PASSWORD = "Product-metrics-test-password-1";
    static final String[] TABLES = {"product_metrics_switch", "product_metrics_onboarding_progress",
            "product_metrics_onboarding_daily", "product_metrics_transfer_daily"};

    @LocalServerPort private int port;
    @Autowired LocalTokenService localTokenService;
    @Autowired ManagementUserService managementUserService;
    @Autowired ManagementUserRepository managementUserRepository;
    @Autowired ProductMetricsService service;
    @Autowired ProductMetricsStore store;
    @Autowired ProductMetricsRateLimiter rateLimiter;
    @Autowired ProductMetricsProperties properties;
    @Autowired JdbcTemplate jdbcTemplate;
    @MockitoBean ProductMetricsClock clock;

    private final AtomicLong nowMs = new AtomicLong();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    void pinTheClockAndEmptyTheStore() {
        when(clock.millis()).thenAnswer(invocation -> nowMs.get());
        freshState();
    }

    /** No accounts, no metrics rows, an empty limiter with the default budgets, metrics allowed. */
    void freshState() {
        for (String table : TABLES) {
            jdbcTemplate.update("DELETE FROM " + table);
        }
        managementUserRepository.deleteAllInBatch();
        properties.setAllowed(true);
        limits(ProductMetricsModel.DEFAULT_PER_USER_EVENTS_PER_MINUTE,
                ProductMetricsModel.DEFAULT_PER_TENANT_EVENTS_PER_MINUTE);
    }

    void limits(int perUser, int perTenant) {
        properties.setPerUserEventsPerMinute(perUser);
        properties.setPerTenantEventsPerMinute(perTenant);
        rateLimiter.clear();
    }

    void at(long epochMillis) {
        nowMs.set(epochMillis);
    }

    // -- accounts -----------------------------------------------------------------------------------

    static ManagementContext tenantAdmin(String tenantId) {
        return new ManagementContext(new TenantContext(tenantId), "product-metrics-fixture-admin", true);
    }

    void createUser(String tenantId, String username, boolean admin) {
        managementUserService.createUser(tenantAdmin(tenantId), new ManagementUserService.UserMutation(
                username, PASSWORD, admin ? ManagementRole.ADMIN : ManagementRole.USER, true));
    }

    /** A token as /auth/login issues it; the role claim is ignored, the account is re-read per request. */
    String token(String tenantId, String username) {
        return localTokenService.issueToken(username, tenantId, ManagementRole.USER);
    }

    // -- HTTP ---------------------------------------------------------------------------------------

    HttpResponse<String> send(String method, String path, String token, byte[] body) {
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body);
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, publisher);
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        try {
            return httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    HttpResponse<String> send(String method, String path, String token, String body) {
        return send(method, path, token, body == null ? null : body.getBytes(StandardCharsets.UTF_8));
    }

    static JsonNode json(HttpResponse<String> response) {
        try {
            return JSON.readTree(response.body());
        } catch (IOException e) {
            throw new IllegalStateException("not JSON: " + response.body(), e);
        }
    }
}
