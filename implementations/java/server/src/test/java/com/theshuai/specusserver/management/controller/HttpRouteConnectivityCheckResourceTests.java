package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.connectivity.HttpRouteConnectivityCheckService;
import com.theshuai.specusserver.connectivity.HttpRouteConnectivityTargets;
import com.theshuai.specusserver.connectivity.NatConnectivityProbe;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.management.service.HttpShareService;
import com.theshuai.specusserver.management.service.NatControlService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.session.ClientHttpRouteCapabilities;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

/**
 * {@code POST /api/admin/http-routes/{routeId}/connectivity-check} with the real route visibility of
 * {@link HttpRouteService}, the real route records adapter and the real NAT probe: who may check a
 * route, which bodies are refused, and what a visible route of an offline client answers.
 */
class HttpRouteConnectivityCheckResourceTests {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String TENANT = "t1";
    private static final long ROUTE_ID = 7L;
    private static final long CLIENT_ID = 2L;

    private final HttpRouteMappingRepository routeRepository = mock(HttpRouteMappingRepository.class);
    private final ClientAccountRepository accountRepository = mock(ClientAccountRepository.class);
    private final ManagementContextResolver resolver = mock(ManagementContextResolver.class);
    private final String clientName = "offline-" + UUID.randomUUID();

    @BeforeEach
    void routeOfAliceOnAnOfflineClient() {
        HttpRouteMapping route = new HttpRouteMapping();
        route.setId(ROUTE_ID);
        route.setTenantId(TENANT);
        route.setClientId(CLIENT_ID);
        route.setClientName(clientName);
        route.setRoute("api");
        route.setTargetBaseUrl("http://10.0.0.5:8080/base");
        route.setEnabled(true);
        when(routeRepository.findByIdAndTenantId(ROUTE_ID, TENANT)).thenReturn(Optional.of(route));

        ClientAccount account = new ClientAccount();
        account.setId(CLIENT_ID);
        account.setTenantId(TENANT);
        account.setOwnerUsername("alice");
        account.setClientName(clientName);
        account.setEnabled(true);
        when(accountRepository.findByIdAndTenantId(CLIENT_ID, TENANT)).thenReturn(Optional.of(account));
        when(accountRepository.findByIdAndTenantIdAndOwnerUsername(CLIENT_ID, TENANT, "alice"))
                .thenReturn(Optional.of(account));
    }

    @Test
    void aVisibleRouteOfAnOfflineClientIsCheckedAndStopsAtTheDevice() throws Exception {
        for (ManagementContext caller : List.of(caller(TENANT, "alice", false), caller(TENANT, "root", true))) {
            MockHttpServletResponse response = perform(newEndpoint(), caller, check(ROUTE_ID).content(""));

            assertThat(response.getStatus()).as(caller.username()).isEqualTo(200);
            assertThat(response.getHeader("Cache-Control")).isEqualTo("private, no-store");
            assertThat(response.getHeader("Retry-After")).isNull();
            JsonNode body = JSON.readTree(response.getContentAsByteArray());
            assertThat(body.path("checkedAt").asText()).matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z");
            ((com.fasterxml.jackson.databind.node.ObjectNode) body).remove("checkedAt");
            assertThat(body).isEqualTo(JSON.readTree("""
                    {"schemaVersion":1,"kind":"http-route","routeId":7,"outcome":"failed",
                     "stoppedAt":"device-online","code":"DEVICE_OFFLINE","totalMs":0,"requests":[],
                     "stages":[
                       {"stage":"configured","result":"passed","code":"CONFIGURED","atMs":0},
                       {"stage":"device-online","result":"failed","code":"DEVICE_OFFLINE","atMs":0},
                       {"stage":"target-reachable","result":"skipped"},
                       {"stage":"access-succeeded","result":"skipped"}]}
                    """));
            // No target address, no path: the stored targetBaseUrl never leaves the server.
            assertThat(response.getContentAsString(StandardCharsets.UTF_8)).doesNotContain("10.0.0.5", "/base");
        }
    }

    @Test
    void anUnknownRouteAndARouteTheCallerCannotSeeAnswerTheSame404() throws Exception {
        MockMvc mvc = newEndpoint();
        List<MockHttpServletResponse> answers = List.of(
                perform(mvc, caller(TENANT, "root", true), check(999L)),
                // Another owner's route, for a user who is not an admin.
                perform(mvc, caller(TENANT, "bob", false), check(ROUTE_ID)),
                // An admin of another tenant.
                perform(mvc, caller("t2", "root", true), check(ROUTE_ID)),
                perform(mvc, caller(TENANT, "alice", false), post("/api/admin/http-routes/abc/connectivity-check")),
                perform(mvc, caller(TENANT, "alice", false), post("/api/admin/http-routes/0/connectivity-check")),
                perform(mvc, caller(TENANT, "alice", false), post("/api/admin/http-routes/-7/connectivity-check")),
                perform(mvc, caller(TENANT, "alice", false),
                        post("/api/admin/http-routes/99999999999999999999/connectivity-check")));

        for (MockHttpServletResponse response : answers) {
            assertThat(response.getStatus()).isEqualTo(404);
            assertThat(response.getContentAsString(StandardCharsets.UTF_8))
                    .isEqualTo("{\"code\":\"CHECK_TARGET_NOT_FOUND\"}");
            assertThat(response.getHeader("Cache-Control")).isEqualTo("private, no-store");
            assertThat(response.getHeader("Retry-After")).isNull();
        }
    }

    @Test
    void withoutAManagementSessionTheAnswerIs401() throws Exception {
        when(resolver.resolve(any())).thenThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "缺少认证身份"));

        MockHttpServletResponse response = newEndpoint()
                .perform(check(ROUTE_ID).content("{\"path\":\"/\"}")).andReturn().getResponse();

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("Cache-Control")).isEqualTo("private, no-store");
        assertThat(JSON.readTree(response.getContentAsByteArray()).has("code")).isFalse();
        verifyNoInteractions(routeRepository);
    }

    @Test
    void invalidBodiesAndPathsAre400BeforeTheRouteIsLookedUp() throws Exception {
        MockMvc mvc = newEndpoint();
        List<String> bodies = List.of(
                "[]", "null", "1", "\"/\"", "{", "{} {}", "{}x",
                "{\"path\":1}", "{\"path\":null}", "{\"path\":[\"/\"]}", "{\"path\":{}}",
                "{\"other\":\"/\"}", "{\"path\":\"/\",\"timeoutMs\":5}",
                "{\"path\":\"/" + "a".repeat(4090) + "\"}",
                path(""), path("healthz"), path("//evil.example/x"), path("/a?b=1"), path("/a#frag"),
                path("/a b"), path("/a\\\\b"), path("/a\\tb"), path("/%zz"), path("/%2"), path("/a%"),
                path("/./a"), path("/a/.."), path("/a/%2e%2E/b"), path("/%2E"), path("/caf\\u00e9"),
                path("/" + "a".repeat(256)), path("/a\\\"b"), path("/a<b>"), path("/a[0]"));

        for (String body : bodies) {
            // An unknown route: the body is judged first.
            MockHttpServletResponse response = perform(mvc, caller(TENANT, "root", true),
                    check(999L).content(body));

            assertThat(response.getStatus()).as(body).isEqualTo(400);
            assertThat(response.getContentAsString(StandardCharsets.UTF_8)).as(body)
                    .isEqualTo("{\"code\":\"CHECK_REQUEST_INVALID\"}");
            assertThat(response.getHeader("Cache-Control")).as(body).isEqualTo("private, no-store");
        }
        verifyNoInteractions(routeRepository);
    }

    @Test
    void validBodiesAndPathsAreChecked() throws Exception {
        List<MockHttpServletRequestBuilder> requests = List.of(
                check(ROUTE_ID),
                check(ROUTE_ID).content(" \r\n\t"),
                check(ROUTE_ID).content("{}"),
                check(ROUTE_ID).content(path("/")),
                check(ROUTE_ID).content(path("/a//b")),
                check(ROUTE_ID).content(path("/%2Fx/%41")),
                check(ROUTE_ID).content(path("/.well-known/health")),
                check(ROUTE_ID).content(path("/a..b/...")),
                check(ROUTE_ID).content(path("/-._~!$&'()*+,;=:@")),
                check(ROUTE_ID).content(path("/" + "a".repeat(255))),
                // Content-Type is not enforced.
                check(ROUTE_ID).contentType(MediaType.TEXT_PLAIN).content(path("/healthz")),
                post("/api/admin/http-routes/" + ROUTE_ID + "/connectivity-check").content(path("/healthz")));

        for (MockHttpServletRequestBuilder request : requests) {
            // A fresh endpoint each time: an executed check takes the route's rate.
            MockHttpServletResponse response = perform(newEndpoint(), caller(TENANT, "root", true), request);

            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(JSON.readTree(response.getContentAsByteArray()).path("code").asText()).isEqualTo("DEVICE_OFFLINE");
        }
    }

    @Test
    void unreadableRecordsAre503NotNotConfigured() throws Exception {
        when(routeRepository.findByIdAndTenantId(anyLong(), anyString()))
                .thenThrow(new DataAccessResourceFailureException("database unavailable"));

        MockHttpServletResponse response = perform(newEndpoint(), caller(TENANT, "root", true), check(ROUTE_ID));

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getContentAsString(StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"CHECK_UNAVAILABLE\"}");
        assertThat(response.getHeader("Retry-After")).isEqualTo("1");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("private, no-store");
    }

    @Test
    void theSameRouteIsRateLimitedForEveryCaller() throws Exception {
        MockMvc mvc = newEndpoint();
        assertThat(perform(mvc, caller(TENANT, "alice", false), check(ROUTE_ID)).getStatus()).isEqualTo(200);

        MockHttpServletResponse limited = perform(mvc, caller(TENANT, "root", true), check(ROUTE_ID));

        assertThat(limited.getStatus()).isEqualTo(429);
        assertThat(limited.getContentAsString(StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"CHECK_RATE_LIMITED\"}");
        assertThat(Long.parseLong(limited.getHeader("Retry-After"))).isBetween(1L, 10L);
        assertThat(limited.getHeader("Cache-Control")).isEqualTo("private, no-store");
    }

    private MockMvc newEndpoint() {
        HttpRouteService routes = new HttpRouteService(routeRepository, accountRepository, mock(NatControlService.class),
                mock(HttpShareService.class));
        HttpRouteConnectivityCheckService service = new HttpRouteConnectivityCheckService(
                new HttpRouteConnectivityTargets(routes, accountRepository),
                new NatConnectivityProbe(new ClientHttpRouteCapabilities()));
        return standaloneSetup(new HttpRouteResource(routes, mock(HttpShareService.class), resolver, service))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver())
                .build();
    }

    private MockHttpServletResponse perform(MockMvc mvc, ManagementContext caller,
                                            MockHttpServletRequestBuilder request) throws Exception {
        when(resolver.resolve(any())).thenReturn(caller);
        return mvc.perform(request).andReturn().getResponse();
    }

    private static MockHttpServletRequestBuilder check(long routeId) {
        return post("/api/admin/http-routes/" + routeId + "/connectivity-check")
                .contentType(MediaType.APPLICATION_JSON);
    }

    /** A body with this path, written as a JSON string literal (escapes are passed through). */
    private static String path(String jsonStringContent) {
        return "{\"path\":\"" + jsonStringContent + "\"}";
    }

    private static ManagementContext caller(String tenantId, String username, boolean admin) {
        return new ManagementContext(new TenantContext(tenantId), username, admin);
    }
}
