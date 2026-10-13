package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.LocalTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.theshuai.specusserver.management.service.NatControlSizingVectorTests.TARGET_PREFIX;
import static com.theshuai.specusserver.management.service.NatControlSizingVectorTests.jsonBytes;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Replays the management steps of {@code protocol/test-vectors/nat-control-size-v1.json} over HTTP
 * against the whole application on an in-memory SQLite store: a route that takes the client's
 * NAT_CONTROL to exactly 1 MiB is accepted, one byte more is refused with 400, and so is creating or
 * enabling another enabled mapping or route; changes that leave entries disabled are accepted.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:sqlite::memory:",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false",
                "specus.client-packages.github-release-fallback-enabled=false"
        })
class NatControlSizeLimitHttpTests {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String TENANT = TenantContext.DEFAULT_TENANT_ID;

    @LocalServerPort private int port;
    @Autowired private NatControlService natControlService;
    @Autowired private ManagementUserService managementUserService;
    @Autowired private LocalTokenService localTokenService;
    @Autowired private ClientAccountRepository clientAccountRepository;
    @Autowired private HttpRouteMappingRepository httpRouteMappingRepository;
    @Autowired private SpecusMappingRepository specusMappingRepository;

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final Map<String, Long> routes = new HashMap<>();
    private final Map<String, Long> mappings = new HashMap<>();
    private ClientAccount client;
    private String token;
    private int nextPort = 42_000;

    @Test
    void managementStepsMatchTheVector() throws Exception {
        JsonNode vector = NatControlSizingVectorTests.readVector();
        int limit = vector.get("messageBodyLimitBytes").asInt();
        int maxJson = vector.get("maxJsonBytesWithEmptyClientName").asInt();
        String errorContains = vector.get("errorContains").asText();
        JsonNode management = vector.get("management");

        managementUserService.createUser(new ManagementContext(new TenantContext(TENANT), "nat-size-fixture", true),
                new ManagementUserService.UserMutation("nat-size-admin", "Nat-size-test-password-1",
                        ManagementRole.ADMIN, true));
        token = localTokenService.issueToken("nat-size-admin", TENANT, ManagementRole.ADMIN);
        client = createClient();
        fill(maxJson - management.get("fillRemainingJsonBytes").asInt());

        int index = 0;
        for (JsonNode step : management.get("steps")) {
            String op = step.get("op").asText();
            String routeName = step.path("route").asText(null);
            String mappingName = step.path("mapping").asText(null);
            String label = "step " + index++ + " " + op + " " + (routeName != null ? routeName : mappingName);
            Boolean enabled = step.has("enabled") ? step.get("enabled").asBoolean() : null;
            boolean exact = "exact".equals(step.path("targetBaseUrl").asText(null));
            String before = stored();

            HttpResponse<String> response = switch (op) {
                case "createRoute" -> send("POST", "/api/admin/clients/" + client.getId() + "/http-routes",
                        body("route", routeName,
                                "targetBaseUrl", exact ? exactTarget(routeName, maxJson) : step.get("targetBaseUrl").asText(),
                                "enabled", enabled));
                case "createMapping" -> send("POST", "/api/admin/clients/" + client.getId() + "/specus-mappings",
                        body("listenPort", ++nextPort, "targetAddress", "127.0.0.1", "targetPort", 8080,
                                "enabled", enabled));
                case "updateRoute" -> {
                    HttpRouteMapping route = httpRouteMappingRepository.findById(routes.get(routeName)).orElseThrow();
                    int grow = step.path("growTargetBaseUrlBy").asInt(0);
                    yield send("PUT", "/api/admin/http-routes/" + route.getId(), body(
                            "route", route.getRoute(),
                            "targetBaseUrl", route.getTargetBaseUrl() + "g".repeat(grow),
                            "enabled", enabled != null ? enabled : route.isEnabled(),
                            "detailCaptureEnabled", step.has("detailCaptureEnabled")
                                    ? step.get("detailCaptureEnabled").asBoolean()
                                    : Boolean.TRUE.equals(route.getDetailCaptureEnabled())));
                }
                case "updateMapping" -> {
                    SpecusMapping mapping = specusMappingRepository.findById(mappings.get(mappingName)).orElseThrow();
                    yield send("PUT", "/api/admin/specus-mappings/" + mapping.getId(), body(
                            "listenPort", mapping.getListenPort(), "targetAddress", mapping.getTargetAddress(),
                            "targetPort", mapping.getTargetPort(),
                            "enabled", enabled != null ? enabled : mapping.isEnabled()));
                }
                case "deleteRoute" -> send("DELETE", "/api/admin/http-routes/" + routes.get(routeName), null);
                default -> throw new IllegalStateException(label + ": unknown op");
            };

            assertThat(response.statusCode()).as("%s: %s", label, response.body())
                    .isEqualTo(step.get("expect").asInt());
            if (response.statusCode() == 400) {
                assertThat(JSON.readTree(response.body()).get("error").asText()).as(label).contains(errorContains);
                assertThat(stored()).as("%s: the refused change was stored", label).isEqualTo(before);
            } else if (op.startsWith("create")) {
                long id = JSON.readTree(response.body()).get("id").asLong();
                (routeName != null ? routes : mappings).put(routeName != null ? routeName : mappingName, id);
            }

            // Whatever was accepted still reaches the client: its NAT_CONTROL fits with the room for any name.
            List<SpecusMapping> enabledMappings = enabledMappings();
            List<HttpRouteMapping> enabledRoutes = enabledRoutes();
            assertThat(natControlService.reservedBodyBytes(enabledMappings, enabledRoutes))
                    .as("%s: the accepted configuration", label).isLessThanOrEqualTo(limit);
            if (exact) {
                assertThat(jsonBytes(natControlService, enabledMappings, enabledRoutes)).as(label).isEqualTo(maxJson);
            }
        }
    }

    private ClientAccount createClient() {
        String now = Instant.now().toString();
        ClientAccount account = new ClientAccount();
        account.setId(6_000_000_001L);
        account.setTenantId(TENANT);
        account.setOwnerUsername("nat-size-admin");
        account.setClientName("nat-control-size");
        account.setPasswordHash("0".repeat(64));
        account.setEnabled(true);
        account.setCreatedAt(now);
        account.setUpdatedAt(now);
        return clientAccountRepository.saveAndFlush(account);
    }

    /** Writes enabled routes straight to the store until the NAT_CONTROL JSON is exactly target bytes. */
    private void fill(int target) {
        int padding = 32 * 1024;
        List<HttpRouteMapping> filled = new ArrayList<>();
        while (jsonBytes(natControlService, List.of(), plus(filled, filler(filled.size(), padding))) + 100 <= target) {
            filled.add(filler(filled.size(), padding));
        }
        HttpRouteMapping last = filler(filled.size(), 0);
        last.setTargetBaseUrl(last.getTargetBaseUrl()
                + "f".repeat(target - jsonBytes(natControlService, List.of(), plus(filled, last))));
        filled.add(last);
        assertThat(jsonBytes(natControlService, List.of(), filled)).isEqualTo(target);
        httpRouteMappingRepository.saveAllAndFlush(filled);
    }

    private HttpRouteMapping filler(int index, int pad) {
        String now = Instant.now().toString();
        HttpRouteMapping route = NatControlSizingVectorTests.route(700_000L + index, "fill-%03d".formatted(index),
                TARGET_PREFIX + "f".repeat(pad));
        route.setTenantId(TENANT);
        route.setClientId(client.getId());
        route.setClientName(client.getClientName());
        route.setCreatedAt(now);
        route.setUpdatedAt(now);
        return route;
    }

    /** The target that brings the NAT_CONTROL JSON to exactly maxJson bytes once the route joins. */
    private String exactTarget(String route, int maxJson) {
        HttpRouteMapping probe = NatControlSizingVectorTests.route(null, route, TARGET_PREFIX);
        int missing = maxJson - jsonBytes(natControlService, enabledMappings(), plus(enabledRoutes(), probe));
        assertThat(missing).as("room left for route %s", route).isNotNegative();
        return TARGET_PREFIX + "e".repeat(missing);
    }

    private List<SpecusMapping> enabledMappings() {
        return specusMappingRepository.findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(TENANT, client.getId());
    }

    private List<HttpRouteMapping> enabledRoutes() {
        return httpRouteMappingRepository.findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(TENANT, client.getId());
    }

    /** Every mapping and route of the client, enabled or not, to compare across a refusal. */
    private String stored() {
        StringBuilder text = new StringBuilder();
        for (SpecusMapping mapping : specusMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(TENANT, client.getId())) {
            text.append(Arrays.asList(mapping.getId(), mapping.getListenPort(), mapping.getTargetAddress(),
                    mapping.getTargetPort(), mapping.isEnabled(), mapping.getUpdatedAt())).append('\n');
        }
        for (HttpRouteMapping route : httpRouteMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(TENANT, client.getId())) {
            text.append(Arrays.asList(route.getId(), route.getRoute(), route.getTargetBaseUrl(), route.isEnabled(),
                    Boolean.TRUE.equals(route.getDetailCaptureEnabled()), route.getUpdatedAt())).append('\n');
        }
        return text.toString();
    }

    private static <T> List<T> plus(List<T> list, T item) {
        List<T> copy = new ArrayList<>(list);
        copy.add(item);
        return copy;
    }

    private static Map<String, Object> body(Object... pairs) {
        Map<String, Object> body = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            body.put((String) pairs[i], pairs[i + 1]);
        }
        return body;
    }

    private HttpResponse<String> send(String method, String path, Map<String, Object> body)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Authorization", "Bearer " + token);
        if (body == null) {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            request.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)));
        }
        return httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
}
