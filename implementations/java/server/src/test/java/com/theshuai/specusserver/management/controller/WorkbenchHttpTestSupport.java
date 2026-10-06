package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementWorkbenchItem;
import com.theshuai.specusserver.management.model.PeerMeshSharedService;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.repository.ManagementWorkbenchItemRepository;
import com.theshuai.specusserver.management.repository.PeerMeshSharedServiceRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.WorkbenchClock;
import com.theshuai.specusserver.management.service.WorkbenchRateLimiter;
import com.theshuai.specusserver.management.service.WorkbenchService;
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
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.mockito.Mockito.when;

/**
 * Shared fixture of the workbench HTTP tests: the whole application on a random port (security
 * filter chain, token decoding, the shared {@code ManagementContextResolver}, the controllers and the
 * transactional services) over an in-memory SQLite store, with the workbench clock pinned by the
 * test. Accounts are created through {@link ManagementUserService} and bearer tokens are minted the
 * way {@code /auth/login} mints them; clients and services are inserted directly so their ids are
 * exactly the ones a test asks for.
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
                // The tests trigger the retention sweep themselves, at the pinned time.
                "specus.workbench.sweep-initial-delay-ms=86400000"
        })
abstract class WorkbenchHttpTestSupport {
    static final Instant BASE_TIME = Instant.parse("2026-10-06T00:00:00Z");
    static final String TABLE = "management_workbench_item";
    static final ObjectMapper JSON = new ObjectMapper();
    static final String PASSWORD = "Workbench-test-password-1";
    private static final AtomicLong SEQUENCE = new AtomicLong(1_000L);

    @LocalServerPort private int port;
    @Autowired LocalTokenService localTokenService;
    @Autowired ManagementUserService managementUserService;
    @Autowired ManagementUserRepository managementUserRepository;
    @Autowired ClientAccountRepository clientAccountRepository;
    @Autowired HttpRouteMappingRepository httpRouteMappingRepository;
    @Autowired SpecusMappingRepository specusMappingRepository;
    @Autowired PeerMeshSharedServiceRepository peerMeshSharedServiceRepository;
    @Autowired ManagementWorkbenchItemRepository workbenchItemRepository;
    @Autowired WorkbenchRateLimiter workbenchRateLimiter;
    @Autowired WorkbenchService workbenchService;
    @Autowired JdbcTemplate jdbcTemplate;
    @MockitoBean WorkbenchClock workbenchClock;

    private final AtomicLong nowMs = new AtomicLong(BASE_TIME.toEpochMilli());
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private boolean storeDown;

    @BeforeEach
    void pinTheWorkbenchClock() {
        when(workbenchClock.millis()).thenAnswer(invocation -> nowMs.get());
        freshState();
    }

    /** Empty store, no accounts, clients or services, an empty limiter, the clock at baseTime. */
    void freshState() {
        storeUp();
        workbenchItemRepository.deleteAllInBatch();
        httpRouteMappingRepository.deleteAllInBatch();
        specusMappingRepository.deleteAllInBatch();
        peerMeshSharedServiceRepository.deleteAllInBatch();
        clientAccountRepository.deleteAllInBatch();
        managementUserRepository.deleteAllInBatch();
        workbenchRateLimiter.clear();
        at(0);
    }

    /** Pins the workbench clock at baseTime + atMs. */
    void at(long atMs) {
        nowMs.set(BASE_TIME.toEpochMilli() + atMs);
    }

    /** The store fails every read and write: the table is moved away, nothing else changes. */
    void storeDown() {
        if (!storeDown) {
            jdbcTemplate.execute("ALTER TABLE " + TABLE + " RENAME TO " + TABLE + "_offline");
            storeDown = true;
        }
    }

    void storeUp() {
        if (storeDown) {
            jdbcTemplate.execute("ALTER TABLE " + TABLE + "_offline RENAME TO " + TABLE);
            storeDown = false;
        }
    }

    // -- accounts ---------------------------------------------------------------------------------

    static ManagementContext tenantAdmin(String tenantId) {
        return new ManagementContext(new TenantContext(tenantId), "workbench-fixture-admin", true);
    }

    /** Creates the account through the existing account management and returns a bearer token for it. */
    String createUser(String tenantId, String username, boolean admin) {
        managementUserService.createUser(tenantAdmin(tenantId), new ManagementUserService.UserMutation(
                username, PASSWORD, admin ? ManagementRole.ADMIN : ManagementRole.USER, true));
        return token(tenantId, username);
    }

    /** A token as /auth/login issues it; the role claim is ignored, the account is re-read per request. */
    String token(String tenantId, String username) {
        return localTokenService.issueToken(username, tenantId, ManagementRole.USER);
    }

    // -- clients and services ---------------------------------------------------------------------

    ClientAccount createClient(String tenantId, String ownerUsername) {
        long id = SEQUENCE.incrementAndGet();
        String now = Instant.now().toString();
        ClientAccount client = new ClientAccount();
        client.setId(5_000_000_000L + id);
        client.setTenantId(tenantId);
        client.setOwnerUsername(ownerUsername);
        client.setClientName("workbench-client-" + id);
        client.setPasswordHash("0".repeat(64));
        client.setEnabled(true);
        client.setCreatedAt(now);
        client.setUpdatedAt(now);
        return clientAccountRepository.saveAndFlush(client);
    }

    /** Inserts a route, mapping or Peer service with exactly this id on the given client. */
    void createObject(String kind, long id, ClientAccount client) {
        String now = Instant.now().toString();
        long sequence = SEQUENCE.incrementAndGet();
        switch (kind) {
            case "http-route" -> {
                HttpRouteMapping route = new HttpRouteMapping();
                route.setId(id);
                route.setTenantId(client.getTenantId());
                route.setClientId(client.getId());
                route.setClientName(client.getClientName());
                route.setRoute("r" + sequence);
                route.setTargetBaseUrl("http://127.0.0.1:8080");
                route.setEnabled(true);
                route.setCreatedAt(now);
                route.setUpdatedAt(now);
                httpRouteMappingRepository.saveAndFlush(route);
            }
            case "tcp-mapping" -> {
                SpecusMapping mapping = new SpecusMapping();
                mapping.setId(id);
                mapping.setTenantId(client.getTenantId());
                mapping.setClientId(client.getId());
                mapping.setClientName(client.getClientName());
                mapping.setListenPort(20_000 + (int) (sequence % 40_000));
                mapping.setTargetAddress("127.0.0.1");
                mapping.setTargetPort(22);
                mapping.setEnabled(true);
                mapping.setCreatedAt(now);
                mapping.setUpdatedAt(now);
                specusMappingRepository.saveAndFlush(mapping);
            }
            case "peer-service" -> {
                PeerMeshSharedService service = new PeerMeshSharedService();
                service.setId(id);
                service.setTenantId(client.getTenantId());
                service.setClientId(client.getId());
                service.setClientName(client.getClientName());
                service.setServiceId("svc-" + sequence);
                service.setName("service " + sequence);
                service.setApplication("http");
                service.setTargetHost("127.0.0.1");
                service.setTargetPort(8080);
                service.setPublishedPort(18080);
                service.setCreatedAt(now);
                service.setUpdatedAt(now);
                peerMeshSharedServiceRepository.saveAndFlush(service);
            }
            default -> throw new IllegalArgumentException(kind);
        }
    }

    void insertRow(String tenantId, String username, String list, String kind, long id, long atMs) {
        workbenchItemRepository.saveAndFlush(new ManagementWorkbenchItem(
                new ManagementWorkbenchItem.Key(tenantId, username, list, kind, id), BASE_TIME.toEpochMilli() + atMs));
    }

    // -- store contents ---------------------------------------------------------------------------

    /** One stored row, its time relative to baseTime, as the vector's rowsAfter spells it. */
    record Row(String tenantId, String username, String list, String kind, long id, long atMs) {
    }

    static final Comparator<Row> ROW_ORDER = Comparator.comparing(Row::tenantId)
            .thenComparing(Row::username)
            .thenComparing(Row::list)
            .thenComparingInt(row -> WorkbenchService.KINDS.indexOf(row.kind()))
            .thenComparingLong(Row::id);

    List<Row> rows() {
        return workbenchItemRepository.findAll().stream()
                .map(item -> new Row(item.getKey().tenantId(), item.getKey().username(), item.getKey().listName(),
                        item.getKey().kind(), item.getKey().objectId(), item.getAtMs() - BASE_TIME.toEpochMilli()))
                .sorted(ROW_ORDER)
                .toList();
    }

    // -- HTTP -------------------------------------------------------------------------------------

    HttpResponse<String> send(String method, String path, String token) {
        return send(method, path, token, null);
    }

    HttpResponse<String> send(String method, String path, String token, String body) {
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body);
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, publisher);
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        try {
            return httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    static JsonNode json(HttpResponse<String> response) {
        try {
            return JSON.readTree(response.body());
        } catch (IOException e) {
            throw new IllegalStateException("not JSON: " + response.body(), e);
        }
    }
}
