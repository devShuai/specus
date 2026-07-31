package com.theshuai.specusserver.management.controller;

import com.sun.net.httpserver.HttpServer;
import com.theshuai.specusserver.config.OidcProperties;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.ManagementUserService.LoginUser;
import com.theshuai.specusserver.management.service.RegistrationService;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.security.TurnstileVerifier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OidcControllerTests {
    private HttpServer tokenServer;
    private String tokenEndpoint;
    private final AtomicReference<String> authorization = new AtomicReference<>();

    @BeforeEach
    void startTokenServer() throws Exception {
        tokenServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        tokenServer.createContext("/token", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.getRequestBody().readAllBytes();
            byte[] response = """
                    {"access_token":"opaque-certus-token","id_token":"signed-id-token",
                     "token_type":"Bearer","expires_in":3600}
                    """.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        tokenServer.start();
        tokenEndpoint = "http://127.0.0.1:" + tokenServer.getAddress().getPort() + "/token";
    }

    @AfterEach
    void stopTokenServer() {
        tokenServer.stop(0);
    }

    @Test
    void validatesIdTokenAndMintsSpecusTokenForResolvedUser() {
        Fixture fixture = fixture("expected-nonce", "alice", true);
        assertThat(fixture.controller.config())
                .containsEntry("registrationEndpoint", "https://certus.devshuai.com/register");

        ResponseEntity<?> response = fixture.controller.exchange(
                new OidcController.TokenExchangeRequest("code", "verifier", "expected-nonce"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isInstanceOf(Map.class);
        Map<?, ?> body = (Map<?, ?>) response.getBody();
        assertThat(body.get("accessToken")).isEqualTo("local-specus-token");
        assertThat(body.get("idToken")).isEqualTo("signed-id-token");
        assertThat(body.get("expiresIn")).isEqualTo(28800L);
        assertThat(authorization.get()).startsWith("Basic ");
        verify(fixture.localTokenService)
                .issueToken("alice", "default", ManagementRole.USER);
    }

    @Test
    void rejectsIdTokenWhenNonceDoesNotMatch() {
        Fixture fixture = fixture("different-nonce", "alice", true);

        ResponseEntity<?> response = fixture.controller.exchange(
                new OidcController.TokenExchangeRequest("code", "verifier", "expected-nonce"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        verify(fixture.localTokenService, never())
                .issueToken("alice", "default", ManagementRole.USER);
    }

    @Test
    void rejectsCertusIdentityThatCannotBeProvisioned() {
        Fixture fixture = fixture("expected-nonce", "unknown", false);

        ResponseEntity<?> response = fixture.controller.exchange(
                new OidcController.TokenExchangeRequest("code", "verifier", "expected-nonce"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        verify(fixture.localTokenService, never())
                .issueToken("unknown", "default", ManagementRole.USER);
    }

    private Fixture fixture(String tokenNonce, String username, boolean provisioned) {
        OidcProperties properties = new OidcProperties();
        properties.setClientId("specus");
        properties.setClientSecret("client-secret");
        properties.setTokenEndpoint(tokenEndpoint);

        LocalTokenService localTokenService = mock(LocalTokenService.class);
        when(localTokenService.getTtlSeconds()).thenReturn(28800L);
        when(localTokenService.issueToken("alice", "default", ManagementRole.USER))
                .thenReturn("local-specus-token");
        ManagementUserService users = mock(ManagementUserService.class);
        when(users.resolveOrProvisionOidcUser(
                "https://certus.devshuai.com",
                "certus-user-id",
                username)).thenReturn(provisioned
                ? Optional.of(new LoginUser(username, "default", ManagementRole.USER, false))
                : Optional.empty());
        RegistrationService registration = mock(RegistrationService.class);
        TurnstileVerifier turnstile = mock(TurnstileVerifier.class);
        JwtDecoder jwtDecoder = mock(JwtDecoder.class);
        @SuppressWarnings("unchecked")
        ObjectProvider<JwtDecoder> jwtDecoderProvider = mock(ObjectProvider.class);
        when(jwtDecoderProvider.getIfAvailable()).thenReturn(jwtDecoder);
        Instant now = Instant.now();
        Jwt idToken = new Jwt(
                "signed-id-token",
                now,
                now.plusSeconds(300),
                Map.of("alg", "RS256"),
                Map.of(
                        "iss", "https://certus.devshuai.com",
                        "sub", "certus-user-id",
                        "nonce", tokenNonce,
                        "preferred_username", username));
        when(jwtDecoder.decode("signed-id-token")).thenReturn(idToken);

        OidcController controller = new OidcController(
                properties,
                localTokenService,
                users,
                registration,
                turnstile,
                jwtDecoderProvider);
        return new Fixture(controller, localTokenService);
    }

    private record Fixture(OidcController controller, LocalTokenService localTokenService) {
    }
}
