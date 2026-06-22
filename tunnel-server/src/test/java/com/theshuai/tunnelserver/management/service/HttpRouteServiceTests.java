package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.HttpRouteView;
import com.theshuai.tunnelserver.management.model.ClientAccountView;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.service.ClientAccountService.ClientMutation;
import com.theshuai.tunnelserver.management.service.HttpRouteService.RouteMutation;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link HttpRouteService} 的单元测试：在内存 SQLite 上跑真实的 JPA / Spring 事务，
 * 不联在线客户端（{@code SessionUtil.getChannel} 返回 null），所以
 * {@code NatControlService.pushSnapshotIfOnline} 会静默返回；这里只验证 CRUD 与校验语义。
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-http-route?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "tunnel.netty.port=0",
                "tunnel.database.seed-demo-client=false"
        }
)
class HttpRouteServiceTests {

    private static final String CLIENT_A = "RouteClientA";
    private static final String CLIENT_B = "RouteClientB";

    @Autowired private HttpRouteService httpRouteService;
    @Autowired private ClientAccountService clientAccountService;
    @Autowired private ClientAccountRepository clientAccountRepository;
    @Autowired private HttpRouteMappingRepository httpRouteMappingRepository;

    private long clientIdA;
    private long clientIdB;

    @BeforeEach
    void setUp() {
        httpRouteMappingRepository.deleteAll();
        clientAccountRepository.deleteAll();
        clientAccountService.createClient(new ClientMutation(CLIENT_A, "pwa", true, 0));
        clientAccountService.createClient(new ClientMutation(CLIENT_B, "pwb", true, 0));
        clientIdA = clientAccountRepository.findByClientName(CLIENT_A).orElseThrow().getId();
        clientIdB = clientAccountRepository.findByClientName(CLIENT_B).orElseThrow().getId();
    }

    @AfterEach
    void tearDown() {
        httpRouteMappingRepository.deleteAll();
        clientAccountRepository.deleteAll();
    }

    @Test
    void createRoutePersistsRowAndDefaultsEnabledTrue() {
        HttpRouteView view = httpRouteService.createRoute(clientIdA, new RouteMutation("web", "http://127.0.0.1:8080", null));

        assertThat(view.id()).isNotNull();
        assertThat(view.clientId()).isEqualTo(clientIdA);
        assertThat(view.clientName()).isEqualTo(CLIENT_A);
        assertThat(view.route()).isEqualTo("web");
        assertThat(view.targetBaseUrl()).isEqualTo("http://127.0.0.1:8080");
        assertThat(view.enabled()).isTrue();
        assertThat(view.createdAt()).isNotBlank();
        assertThat(view.updatedAt()).isNotBlank();

        assertThat(httpRouteMappingRepository.existsByClientId(clientIdA)).isTrue();
    }

    @Test
    void createRouteDuplicateOnSameClientIsRejected() {
        httpRouteService.createRoute(clientIdA, new RouteMutation("web", "http://127.0.0.1:8080", true));

        assertThatThrownBy(() -> httpRouteService.createRoute(clientIdA,
                new RouteMutation("web", "http://127.0.0.1:9090", true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("已存在");
    }

    @Test
    void sameRouteOnDifferentClientsIsAllowed() {
        httpRouteService.createRoute(clientIdA, new RouteMutation("web", "http://127.0.0.1:8080", true));
        HttpRouteView second = httpRouteService.createRoute(clientIdB,
                new RouteMutation("web", "http://127.0.0.1:9090", true));

        assertThat(second.clientId()).isEqualTo(clientIdB);
        assertThat(httpRouteService.listRoutes(null)).hasSize(2);
    }

    @Test
    void updateRouteRewritesFieldsAndRefreshesTimestamp() throws Exception {
        HttpRouteView created = httpRouteService.createRoute(clientIdA,
                new RouteMutation("web", "http://127.0.0.1:8080", true));
        // 让 updatedAt 至少推进 1ms，避免相同时间戳干扰断言
        Thread.sleep(5);

        HttpRouteView updated = httpRouteService.updateRoute(created.id(),
                new RouteMutation("api", "https://api.example.com", false));

        assertThat(updated.id()).isEqualTo(created.id());
        assertThat(updated.route()).isEqualTo("api");
        assertThat(updated.targetBaseUrl()).isEqualTo("https://api.example.com");
        assertThat(updated.enabled()).isFalse();
        assertThat(updated.updatedAt()).isNotEqualTo(created.updatedAt());
    }

    @Test
    void updateRouteCannotCollideWithExistingRouteOnSameClient() {
        httpRouteService.createRoute(clientIdA, new RouteMutation("web", "http://127.0.0.1:8080", true));
        HttpRouteView second = httpRouteService.createRoute(clientIdA,
                new RouteMutation("api", "http://127.0.0.1:9090", true));

        assertThatThrownBy(() -> httpRouteService.updateRoute(second.id(),
                new RouteMutation("web", "http://127.0.0.1:9091", true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("已存在");
    }

    @Test
    void updateRouteAllowsRenamingToOwnRoute() {
        HttpRouteView created = httpRouteService.createRoute(clientIdA,
                new RouteMutation("web", "http://127.0.0.1:8080", true));

        // route 不变，只改 target —— 不应被自身的唯一约束误判为冲突
        HttpRouteView updated = httpRouteService.updateRoute(created.id(),
                new RouteMutation("web", "http://127.0.0.1:9090", true));

        assertThat(updated.route()).isEqualTo("web");
        assertThat(updated.targetBaseUrl()).isEqualTo("http://127.0.0.1:9090");
    }

    @Test
    void deleteRouteRemovesRow() {
        HttpRouteView created = httpRouteService.createRoute(clientIdA,
                new RouteMutation("web", "http://127.0.0.1:8080", true));

        httpRouteService.deleteRoute(created.id());

        assertThat(httpRouteMappingRepository.findById(created.id())).isEmpty();
        // existsByClientId 仍然 false，等于"未接管态"重新激活
        assertThat(httpRouteMappingRepository.existsByClientId(clientIdA)).isFalse();
    }

    @Test
    void deleteUnknownRouteThrows() {
        assertThatThrownBy(() -> httpRouteService.deleteRoute(999_999_999L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void listRoutesFiltersByClient() {
        httpRouteService.createRoute(clientIdA, new RouteMutation("web", "http://127.0.0.1:8080", true));
        httpRouteService.createRoute(clientIdB, new RouteMutation("api", "http://127.0.0.1:9090", false));

        List<HttpRouteView> all = httpRouteService.listRoutes(null);
        assertThat(all).hasSize(2);

        List<HttpRouteView> only = httpRouteService.listRoutes(clientIdB);
        assertThat(only).hasSize(1);
        assertThat(only.get(0).route()).isEqualTo("api");
    }

    @Test
    void tenantScopedQueriesDoNotLeakClientsOrRoutes() {
        TenantContext tenantB = new TenantContext("tenant-b");
        clientAccountService.createClient(tenantB, new ClientMutation("RouteClientTenantB", "pwc", true, 0));
        long clientIdTenantB = clientAccountRepository.findByClientName("RouteClientTenantB").orElseThrow().getId();

        httpRouteService.createRoute(clientIdA, new RouteMutation("web", "http://127.0.0.1:8080", true));
        httpRouteService.createRoute(tenantB, clientIdTenantB,
                new RouteMutation("api", "http://127.0.0.1:9090", true));

        assertThat(clientAccountService.listClients())
                .extracting(ClientAccountView::clientName)
                .containsExactlyInAnyOrder(CLIENT_A, CLIENT_B);
        assertThat(clientAccountService.listClients(tenantB))
                .extracting(ClientAccountView::clientName)
                .containsExactly("RouteClientTenantB");
        assertThat(httpRouteService.listRoutes(null))
                .extracting(HttpRouteView::route)
                .containsExactly("web");
        assertThat(httpRouteService.listRoutes(tenantB, null))
                .extracting(HttpRouteView::route)
                .containsExactly("api");
    }

    @Test
    void blankRouteIsRejected() {
        assertThatThrownBy(() -> httpRouteService.createRoute(clientIdA,
                new RouteMutation(" ", "http://127.0.0.1:8080", true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("blank");
    }

    @Test
    void slashInRouteIsRejected() {
        assertThatThrownBy(() -> httpRouteService.createRoute(clientIdA,
                new RouteMutation("a/b", "http://127.0.0.1:8080", true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'/'");
    }

    @Test
    void overlongRouteIsRejected() {
        String tooLong = "a".repeat(61);
        assertThatThrownBy(() -> httpRouteService.createRoute(clientIdA,
                new RouteMutation(tooLong, "http://127.0.0.1:8080", true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("too long");
    }

    @Test
    void nonHttpTargetIsRejected() {
        assertThatThrownBy(() -> httpRouteService.createRoute(clientIdA,
                new RouteMutation("web", "ftp://example.com", true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("http(s)");
    }

    @Test
    void targetWithoutHostIsRejected() {
        assertThatThrownBy(() -> httpRouteService.createRoute(clientIdA,
                new RouteMutation("web", "http:///path-only", true)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unknownClientIsRejectedOnCreate() {
        assertThatThrownBy(() -> httpRouteService.createRoute(424242L,
                new RouteMutation("web", "http://127.0.0.1:8080", true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("client not found");
    }
}
