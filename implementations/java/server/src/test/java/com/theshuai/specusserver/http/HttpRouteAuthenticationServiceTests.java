package com.theshuai.specusserver.http;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HttpRouteAuthenticationServiceTests {
    private final ClientAccountService clientAccountService = mock(ClientAccountService.class);
    private final HttpRouteMappingRepository routeRepository = mock(HttpRouteMappingRepository.class);
    private final HttpRouteAuthenticationService service = new HttpRouteAuthenticationService(
            clientAccountService, routeRepository);

    private ClientAccount account;
    private HttpRouteMapping route;

    @BeforeEach
    void setUp() {
        account = new ClientAccount();
        account.setId(42L);
        account.setTenantId("tenant-a");
        account.setClientName("client-a");

        route = new HttpRouteMapping();
        route.setId(7L);
        route.setClientId(42L);
        route.setClientName("client-a");
        route.setRoute("private");
        route.setEnabled(true);
        route.setAuthEnabled(true);
        route.setAuthUsername("viewer");
        route.setAuthPasswordHash(PasswordService.hash("secret:tail"));

        when(clientAccountService.findClientByName("client-a")).thenReturn(Optional.of(account));
        when(routeRepository.findByTenantIdAndClientIdAndRoute("tenant-a", 42L, "private"))
                .thenReturn(Optional.of(route));
    }

    @Test
    void unmanagedRouteRemainsPublicForClientLocalCompatibility() {
        when(routeRepository.findByTenantIdAndClientIdAndRoute("tenant-a", 42L, "legacy"))
                .thenReturn(Optional.empty());

        assertThat(service.authorize("client-a", "legacy", null).outcome())
                .isEqualTo(HttpRouteAuthenticationService.Outcome.PUBLIC);
        assertThat(service.authorize("missing-client", "legacy", null).outcome())
                .isEqualTo(HttpRouteAuthenticationService.Outcome.PUBLIC);
    }

    @Test
    void protectedRouteRequiresValidUtf8BasicCredentials() {
        assertThat(service.authorize("client-a", "private", null).outcome())
                .isEqualTo(HttpRouteAuthenticationService.Outcome.UNAUTHORIZED);
        assertThat(service.authorize("client-a", "private", "Bearer upstream-token").outcome())
                .isEqualTo(HttpRouteAuthenticationService.Outcome.UNAUTHORIZED);
        assertThat(service.authorize("client-a", "private", basic("viewer", "wrong")).outcome())
                .isEqualTo(HttpRouteAuthenticationService.Outcome.UNAUTHORIZED);

        HttpRouteAuthenticationService.Decision authenticated = service.authorize(
                "client-a", "private", basic("viewer", "secret:tail"));
        assertThat(authenticated.outcome()).isEqualTo(HttpRouteAuthenticationService.Outcome.AUTHENTICATED);
        assertThat(authenticated.credentialsConsumed()).isTrue();
    }

    @Test
    void disabledOrMisconfiguredManagedRouteFailsClosed() {
        route.setEnabled(false);
        assertThat(service.authorize("client-a", "private", basic("viewer", "secret:tail")).outcome())
                .isEqualTo(HttpRouteAuthenticationService.Outcome.NOT_FOUND);

        route.setEnabled(true);
        route.setAuthPasswordHash(null);
        assertThat(service.authorize("client-a", "private", basic("viewer", "secret:tail")).outcome())
                .isEqualTo(HttpRouteAuthenticationService.Outcome.UNAVAILABLE);
    }

    @Test
    void databaseLookupFailureFailsClosed() {
        when(routeRepository.findByTenantIdAndClientIdAndRoute("tenant-a", 42L, "private"))
                .thenThrow(new IllegalStateException("database unavailable"));

        assertThat(service.authorize("client-a", "private", basic("viewer", "secret:tail")).outcome())
                .isEqualTo(HttpRouteAuthenticationService.Outcome.UNAVAILABLE);
    }

    private String basic(String username, String password) {
        String value = username + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
