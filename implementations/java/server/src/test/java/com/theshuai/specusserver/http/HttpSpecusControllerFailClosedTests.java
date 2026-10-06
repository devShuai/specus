package com.theshuai.specusserver.http;

import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.HttpMediaCaptureService;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The public entry against the real {@link HttpRouteAuthenticationService}: a route the server has
 * no record of, or one whose client is disabled, never reaches the client's data channel, even
 * though that client (bound below) would still forward the route name from its old route list.
 */
class HttpSpecusControllerFailClosedTests {
    private final ClientAccountService clientAccountService = mock(ClientAccountService.class);
    private final HttpRouteMappingRepository routeRepository = mock(HttpRouteMappingRepository.class);
    private final HttpSpecusController controller = new HttpSpecusController(
            mock(TrafficUsageService.class),
            mock(TrafficInspectionService.class),
            mock(HttpMediaCaptureService.class),
            mock(ResponseRewriter.class),
            clientAccountService,
            routeRepository,
            new HttpRouteAuthenticationService(clientAccountService, routeRepository),
            1_000,
            1_024,
            0);

    private final String clientName = "fail-closed-" + UUID.randomUUID();
    private ClientAccount account;
    private EmbeddedChannel dataChannel;

    @BeforeEach
    void setUp() {
        account = new ClientAccount();
        account.setId(42L);
        account.setTenantId("tenant-a");
        account.setClientName(clientName);
        when(clientAccountService.findClientByName(clientName)).thenReturn(Optional.of(account));

        HttpRouteMapping route = new HttpRouteMapping();
        route.setId(7L);
        route.setClientId(42L);
        route.setClientName(clientName);
        route.setRoute("web");
        route.setTargetBaseUrl("http://127.0.0.1:8080");
        route.setEnabled(true);
        route.setAuthEnabled(true);
        route.setAuthUsername("viewer");
        route.setAuthPasswordHash(PasswordService.hashToken("secret"));
        when(routeRepository.findByTenantIdAndClientIdAndRoute("tenant-a", 42L, "web"))
                .thenReturn(Optional.of(route));

        dataChannel = new EmbeddedChannel(new NatServerHandler(
                null, null, null, null, mock(WebSocketStreamRegistry.class), mock(WebSocketSpecusHandler.class)));
        dataChannel.attr(ServerAttributes.TENANT_ID).set("tenant-a");
        SessionUtil.bindDataSession(new Session(clientName), dataChannel);
    }

    @AfterEach
    void tearDown() {
        dataChannel.finishAndReleaseAll();
    }

    @Test
    void deletedProtectedRouteReturnsNotFoundAndOpensNoStream() throws Exception {
        assertThat(forward("web").getStatus()).isEqualTo(401);
        assertThat(dataChannel.outboundMessages()).isEmpty();

        when(routeRepository.findByTenantIdAndClientIdAndRoute("tenant-a", 42L, "web"))
                .thenReturn(Optional.empty());

        assertThat(forward("web").getStatus()).isEqualTo(404);
        assertThat(dataChannel.outboundMessages()).isEmpty();
    }

    @Test
    void routeOfDisabledClientReturnsNotFoundAndOpensNoStream() throws Exception {
        account.setEnabled(false);

        assertThat(forward("web").getStatus()).isEqualTo(404);
        assertThat(dataChannel.outboundMessages()).isEmpty();
    }

    private MockHttpServletResponse forward(String route) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/http/" + clientName + "/" + route + "/");
        MockHttpServletResponse response = new MockHttpServletResponse();
        controller.forward(clientName, route, request, response);
        return response;
    }
}
