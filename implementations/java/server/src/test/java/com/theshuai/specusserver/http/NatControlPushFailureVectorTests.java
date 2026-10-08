package com.theshuai.specusserver.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.server.NettyServer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Replays {@code existingOversize} of {@code protocol/test-vectors/nat-control-size-v1.json}: a client
 * whose enabled routes, written straight to the store, take its NAT_CONTROL past the 1 MiB MESSAGE
 * body. Its control login stands and the Peer Mesh login push still arrives, the manual pushes answer
 * 409, route changes are stored and answered as usual, and nothing reaches the connection, which stays
 * open, until the configuration is back within the limit. The login goes through the production Netty
 * pipeline, so the push that fails is the one {@code ManagedLoginRequestHandler} starts.
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
                // Peer Mesh on for its login push. Strict RFC 5780 without the addresses it needs
                // keeps the STUN/TURN UDP server from starting, so the test binds no UDP port.
                "specus.peer-mesh.enabled=true",
                "specus.peer-mesh.stun-behavior-strict=true"
        }
)
class NatControlPushFailureVectorTests {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String TENANT = TenantContext.DEFAULT_TENANT_ID;
    private static final String ADMIN = "nat-push-failure-admin";
    private static final String TARGET_PREFIX = "http://127.0.0.1:8080/";
    private static final Duration WAIT = Duration.ofSeconds(5);
    /** How long a NAT_CONTROL that should not come is given to show up anyway. */
    private static final Duration QUIET = Duration.ofMillis(300);

    @Value("${local.server.port}")
    private int port;

    @Autowired private NettyServer nettyServer;
    @Autowired private ManagementUserRepository userRepository;
    @Autowired private HttpRouteMappingRepository routeRepository;
    @Autowired private LocalTokenService tokens;

    private final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

    @Test
    void existingOversizeConfigurationIsNeitherSentNorDisconnecting() throws Exception {
        JsonNode vector = readVector();
        JsonNode scenario = vector.get("existingOversize");
        String errorContains = vector.get("errorContains").asText();

        ensureAdmin();
        String adminToken = tokens.issueToken(ADMIN, TENANT, ManagementRole.ADMIN);
        JsonNode credential = ok(201, send("POST", "/api/admin/client-credentials",
                "{\"enabled\":true,\"maxOnlineInstances\":2}", adminToken));
        JsonNode login = ok(200, send("POST", "/api/client/auth/login", JsonUtil.objectToString(loginRequest(
                credential.get("credential").get("apiKey").asText(), credential.get("secret").asText())), null));
        long clientId = login.get("clientId").asLong();
        String clientName = login.get("clientName").asText();
        List<Long> fill = fill(clientId, clientName, scenario.get("jsonBytesWithEmptyClientName").asInt(),
                scenario.get("fillTargetBaseUrlMaxBytes").asInt());

        FakeTunnelClient client = null;
        try {
            int index = 0;
            for (JsonNode step : scenario.get("steps")) {
                String op = step.get("op").asText();
                String label = "step " + index++ + " " + op;
                HttpResponse<String> response = switch (op) {
                    case "connect" -> {
                        client = FakeTunnelClient.connect(nettyServer.getBoundPort(), clientName,
                                login.get("clientSessionId").asLong(), login.get("accessToken").asText(),
                                new AtomicInteger(), new FakeTunnelClient.Response(200, List.of(), ""));
                        FakeTunnelClient connected = client;
                        await(label + ": the Peer Mesh login push", () -> connected.peerControls().stream()
                                .anyMatch(message -> "peer-config".equals(message.path("type").asText())));
                        yield null;
                    }
                    case "pushNatControl" -> send("POST", "/api/admin/clients/" + clientId + "/nat-control",
                            null, adminToken);
                    case "forceRefreshPortMapping" -> send("POST",
                            "/api/admin/clients/" + clientId + "/force-refresh-port-mapping", null, adminToken);
                    case "createRoute" -> send("POST", "/api/admin/clients/" + clientId + "/http-routes",
                            JSON.createObjectNode()
                                    .put("route", step.get("route").asText())
                                    .put("targetBaseUrl", step.get("targetBaseUrl").asText())
                                    .put("enabled", step.get("enabled").asBoolean())
                                    .toString(), adminToken);
                    case "deleteFillRoute" -> send("DELETE", "/api/admin/http-routes/" + fill.remove(0),
                            null, adminToken);
                    case "shrinkInStore" -> {
                        List<HttpRouteMapping> routes = routeRepository.findAllById(fill);
                        routes.forEach(route -> route.setEnabled(false));
                        routeRepository.saveAllAndFlush(routes);
                        yield null;
                    }
                    default -> throw new IllegalStateException(label + ": unknown op");
                };

                if (step.has("expect")) {
                    assertThat(response.statusCode()).as("%s: %s", label, response.body())
                            .isEqualTo(step.get("expect").asInt());
                    if (response.statusCode() == 409) {
                        assertThat(JSON.readTree(response.body()).get("error").asText()).as(label)
                                .contains(errorContains);
                    }
                }
                assertThat(client).as("%s: connected", label).isNotNull();
                FakeTunnelClient connected = client;
                if (step.path("natControl").asBoolean()) {
                    await(label + ": the NAT_CONTROL", () -> !connected.natControls().isEmpty());
                    for (JsonNode route : connected.natControls().get(0).get("httpSpecusConfigList")) {
                        assertThat(route.get("route").asText()).as(label).doesNotStartWith("fill-");
                    }
                } else {
                    Thread.sleep(QUIET.toMillis());
                    assertThat(connected.natControls()).as("%s: a NAT_CONTROL reached the client", label).isEmpty();
                }
                assertThat(connected.controlOpen()).as("%s: the control connection was closed", label).isTrue();
            }
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    /**
     * Enabled routes written straight to the store, each target fillTargetBaseUrlMaxBytes long, enough
     * of them that the targets alone take the NAT_CONTROL JSON to jsonBytes. Returns their ids.
     */
    private List<Long> fill(long clientId, String clientName, int jsonBytes, int targetBytes) {
        String now = Instant.now().toString();
        String target = TARGET_PREFIX + "f".repeat(targetBytes - TARGET_PREFIX.length());
        int count = (jsonBytes + targetBytes - 1) / targetBytes;
        List<HttpRouteMapping> routes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            HttpRouteMapping route = new HttpRouteMapping();
            route.setId(800_000L + i);
            route.setTenantId(TENANT);
            route.setClientId(clientId);
            route.setClientName(clientName);
            route.setRoute("fill-%04d".formatted(i));
            route.setTargetBaseUrl(target);
            route.setEnabled(true);
            route.setInsecureSkipVerify(false);
            route.setCreatedAt(now);
            route.setUpdatedAt(now);
            routes.add(route);
        }
        return new ArrayList<>(routeRepository.saveAllAndFlush(routes).stream().map(HttpRouteMapping::getId).toList());
    }

    private static void await(String what, BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + WAIT.toNanos();
        while (!condition.getAsBoolean()) {
            assertThat(System.nanoTime() < deadline).as("%s did not arrive within %s", what, WAIT).isTrue();
            Thread.sleep(20);
        }
    }

    private HttpResponse<String> send(String method, String path, String body, String bearer) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
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

    private static JsonNode ok(int status, HttpResponse<String> response) throws IOException {
        assertThat(response.statusCode()).as(response.request().method() + " " + response.uri().getPath()
                + " -> " + response.body()).isEqualTo(status);
        return JSON.readTree(response.body());
    }

    private void ensureAdmin() {
        if (userRepository.findByTenantIdAndLoginNameNormalized(TENANT, ADMIN).isPresent()) {
            return;
        }
        ManagementUser user = new ManagementUser();
        user.setUsername("account-" + ADMIN);
        user.setLoginName(ADMIN);
        user.setLoginNameNormalized(ADMIN);
        user.setTenantId(TENANT);
        user.setPasswordHash("0".repeat(64));
        user.setRole(ManagementRole.ADMIN);
        user.setEnabled(true);
        user.setCreatedAt(Instant.now().toString());
        user.setUpdatedAt(Instant.now().toString());
        userRepository.save(user);
    }

    /** A signed API-key login as the Java client sends it. */
    private static ClientAuthLoginRequest loginRequest(String apiKey, String secret) {
        ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
        environment.setMachineFingerprint("nat-push-failure-" + UUID.randomUUID());
        environment.setHostname("nat-push-failure");
        environment.setOsUser("vector");
        environment.setOsName("JUnit");
        environment.setOsVersion("1");
        environment.setOsArch("test");
        environment.setJavaVersion(System.getProperty("java.version", ""));
        environment.setStartedAt(Instant.now().toString());
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        ClientAuthLoginRequest request = new ClientAuthLoginRequest();
        request.setApiKey(apiKey);
        request.setTimestamp(timestamp);
        request.setNonce(nonce);
        request.setEnvironment(environment);
        request.setSignature(ClientAuthSigner.signApiKey(apiKey, timestamp, nonce, environment, secret));
        return request;
    }

    private static JsonNode readVector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        while (directory != null) {
            Path candidate = directory.resolve("protocol/test-vectors/nat-control-size-v1.json");
            if (Files.isRegularFile(candidate)) {
                return JSON.readTree(Files.readString(candidate, StandardCharsets.UTF_8));
            }
            directory = directory.getParent();
        }
        throw new IllegalStateException("protocol/test-vectors/nat-control-size-v1.json not found");
    }
}
