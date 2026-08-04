package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.ManagementUserService.LoginUser;
import com.theshuai.specusserver.management.service.RegistrationService;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.security.TurnstileVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthControllerRefreshTests {
    private LocalTokenService tokens;
    private ManagementUserService users;
    private AuthController controller;

    @BeforeEach
    void setUp() {
        tokens = mock(LocalTokenService.class);
        users = mock(ManagementUserService.class);
        controller = new AuthController(
                tokens,
                users,
                mock(RegistrationService.class),
                mock(TurnstileVerifier.class));
    }

    @Test
    void refreshUsesCurrentDatabaseTenantAndRole() {
        Jwt jwt = jwt(LocalTokenService.ISSUER, "alice");
        when(users.resolveLocalTokenUser("alice"))
                .thenReturn(Optional.of(new LoginUser(
                        "alice", "current-tenant", ManagementRole.USER, false)));
        when(tokens.issueToken("alice", "current-tenant", ManagementRole.USER))
                .thenReturn("fresh-token");

        var response = controller.refresh(jwt);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isInstanceOf(Map.class);
        assertThat(((Map<?, ?>) response.getBody()).get("accessToken")).isEqualTo("fresh-token");
        verify(tokens).issueToken("alice", "current-tenant", ManagementRole.USER);
    }

    @Test
    void refreshRejectsDisabledOrDeletedLocalUser() {
        Jwt jwt = jwt(LocalTokenService.ISSUER, "alice");
        when(users.resolveLocalTokenUser("alice")).thenReturn(Optional.empty());

        assertThat(controller.refresh(jwt).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(tokens, never()).issueToken(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void refreshStillRejectsExternalOidcToken() {
        Jwt jwt = jwt("https://issuer.example", "alice");

        assertThat(controller.refresh(jwt).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verify(users, never()).resolveLocalTokenUser("alice");
    }

    private Jwt jwt(String issuer, String subject) {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getSubject()).thenReturn(subject);
        when(jwt.getClaims()).thenReturn(Map.of(
                "iss", issuer,
                "sub", subject,
                "tenant_id", "stale-tenant",
                "role", "ADMIN"));
        return jwt;
    }
}
