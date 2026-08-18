package com.theshuai.specusserver.management.security;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.ManagementUserService.LoginUser;
import com.theshuai.specusserver.security.LocalTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ManagementContextResolverTests {
    private ManagementUserService users;
    private ManagementContextResolver resolver;

    @BeforeEach
    void setUp() {
        users = mock(ManagementUserService.class);
        AuthProperties auth = new AuthProperties();
        auth.setUsername("admin");
        resolver = new ManagementContextResolver(auth, users);
    }

    @Test
    void externalClaimsCannotOverrideBoundTenantOrRole() {
        Jwt jwt = jwt("https://issuer.example", "immutable-subject",
                Map.of("role", "ADMIN", "tenant_id", "attacker-tenant"));
        when(users.resolveBoundOidcUser("https://issuer.example", "immutable-subject"))
                .thenReturn(Optional.of(new LoginUser(
                        "alice", "bound-tenant", ManagementRole.USER, false)));

        ManagementContext context = resolver.resolve(jwt);

        assertThat(context.username()).isEqualTo("alice");
        assertThat(context.tenant().tenantId()).isEqualTo("bound-tenant");
        assertThat(context.isAdmin()).isFalse();
    }

    @Test
    void localTokenClaimsCannotPreserveRevokedRole() {
        Jwt jwt = jwt(LocalTokenService.ISSUER, "alice",
                Map.of("role", "ADMIN", "tenant_id", "current-tenant"));
        when(users.resolveLocalTokenUser("alice", "current-tenant"))
                .thenReturn(Optional.of(new LoginUser(
                        "alice", "current-tenant", ManagementRole.USER, false)));

        ManagementContext context = resolver.resolve(jwt);

        assertThat(context.tenant().tenantId()).isEqualTo("current-tenant");
        assertThat(context.isAdmin()).isFalse();
    }

    @Test
    void rejectsUnboundOrDisabledExternalIdentity() {
        Jwt jwt = jwt("https://issuer.example", "unknown", Map.of());
        when(users.resolveBoundOidcUser("https://issuer.example", "unknown"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> resolver.resolve(jwt))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        error -> assertThat(error.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
    }

    private Jwt jwt(String issuer, String subject, Map<String, Object> additionalClaims) {
        Jwt jwt = mock(Jwt.class);
        java.util.LinkedHashMap<String, Object> claims = new java.util.LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", subject);
        claims.putAll(additionalClaims);
        when(jwt.getSubject()).thenReturn(subject);
        when(jwt.getClaims()).thenReturn(claims);
        return jwt;
    }
}
