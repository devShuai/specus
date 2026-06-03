package com.theshuai.tunnelserver.config;

import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelserver.security.LocalTokenService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Locks down the management API with bearer JWTs and leaves everything else open (static page, OIDC
 * and auth helper endpoints, the public {@code /http/**} tunnel ingress). The admin API accepts two
 * token kinds, routed by the JWT {@code alg} header: RS256 from the OIDC gateway (verified via
 * JWKS) and HS256 minted by local username/password login. Only applies in a servlet web context.
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/admin/**").authenticated()
                        .anyRequest().permitAll())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(OidcProperties oidc, LocalTokenService localTokenService) {
        return new AlgorithmRoutingJwtDecoder(oidcDecoder(oidc), localDecoder(localTokenService));
    }

    /** Lazy JWKS-backed decoder for the gateway's RS256 tokens (keys fetched on first use). */
    private JwtDecoder oidcDecoder(OidcProperties oidc) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(oidc.getJwkSetUri()).build();
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        if (StringUtils.hasText(oidc.getIssuer())) {
            validators.add(new JwtIssuerValidator(oidc.getIssuer()));
        }
        if (StringUtils.hasText(oidc.getAudience())) {
            validators.add(audienceValidator(oidc.getAudience()));
        }
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    /** HS256 decoder for the locally-minted password-login tokens. */
    private JwtDecoder localDecoder(LocalTokenService localTokenService) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(localTokenService.getSecretKey())
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                new JwtIssuerValidator(LocalTokenService.ISSUER)));
        return decoder;
    }

    private OAuth2TokenValidator<Jwt> audienceValidator(String audience) {
        OAuth2Error error = new OAuth2Error("invalid_token", "Required audience " + audience + " is missing", null);
        return jwt -> jwt.getAudience() != null && jwt.getAudience().contains(audience)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(error);
    }

    /** Picks the decoder by the JWT header {@code alg}: HS* → local, otherwise → OIDC/JWKS. */
    private static final class AlgorithmRoutingJwtDecoder implements JwtDecoder {
        private final JwtDecoder oidcDecoder;
        private final JwtDecoder localDecoder;

        private AlgorithmRoutingJwtDecoder(JwtDecoder oidcDecoder, JwtDecoder localDecoder) {
            this.oidcDecoder = oidcDecoder;
            this.localDecoder = localDecoder;
        }

        @Override
        public Jwt decode(String token) throws JwtException {
            return isHmac(token) ? localDecoder.decode(token) : oidcDecoder.decode(token);
        }

        private boolean isHmac(String token) {
            int dot = token == null ? -1 : token.indexOf('.');
            if (dot <= 0) {
                return false;
            }
            try {
                byte[] header = Base64.getUrlDecoder().decode(token.substring(0, dot));
                JsonNode node = JsonUtil.readString(new String(header, java.nio.charset.StandardCharsets.UTF_8));
                String alg = node == null ? "" : node.path("alg").asText("");
                return alg.startsWith("HS");
            } catch (RuntimeException e) {
                return false;
            }
        }
    }
}
