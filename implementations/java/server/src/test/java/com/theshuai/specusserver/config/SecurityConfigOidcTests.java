package com.theshuai.specusserver.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityConfigOidcTests {

    @Test
    void oidcValidationFailsClosedWhenIssuerIsNotConfigured() {
        OidcProperties properties = new OidcProperties();
        properties.setIssuer(" ");

        assertTrue(validator(properties).validate(jwt("https://issuer.example")).hasErrors());
    }

    @Test
    void oidcValidationRequiresTheConfiguredIssuer() {
        OidcProperties properties = new OidcProperties();
        properties.setIssuer("https://issuer.example");
        OAuth2TokenValidator<Jwt> validator = validator(properties);

        assertFalse(validator.validate(jwt("https://issuer.example")).hasErrors());
        assertTrue(validator.validate(jwt("https://other.example")).hasErrors());
    }

    @SuppressWarnings("unchecked")
    private static OAuth2TokenValidator<Jwt> validator(OidcProperties properties) {
        try {
            Method method = SecurityConfig.class.getDeclaredMethod("baseOidcValidators", OidcProperties.class);
            method.setAccessible(true);
            List<OAuth2TokenValidator<Jwt>> validators =
                    (List<OAuth2TokenValidator<Jwt>>) method.invoke(new SecurityConfig(), properties);
            return new DelegatingOAuth2TokenValidator<>(validators);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException error) {
            throw new AssertionError(error);
        }
    }

    private static Jwt jwt(String issuer) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .issuer(issuer)
                .subject("subject")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .build();
    }
}
