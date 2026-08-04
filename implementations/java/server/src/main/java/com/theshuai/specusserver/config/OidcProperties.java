package com.theshuai.specusserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * OIDC settings for the management UI login (Authorization Code + PKCE) and optional direct
 * external bearer validation on the admin API. Defaults point at the project's gateway; only
 * {@code clientId} (and the registered {@code redirectUri}) must be supplied for browser login,
 * while direct bearer validation additionally requires a non-blank resource {@code audience}.
 */
@Component
@ConfigurationProperties(prefix = "specus.oidc")
public class OidcProperties {
    private String issuer = "https://certus.devshuai.com";
    private String jwkSetUri = "https://certus.devshuai.com/oauth2/jwks";
    private String authorizationEndpoint = "https://certus.devshuai.com/oauth2/authorize";
    private String registrationEndpoint = "https://certus.devshuai.com/register";
    private String tokenEndpoint = "https://certus.devshuai.com/oauth2/token";
    private String endSessionEndpoint = "https://certus.devshuai.com/oauth2/logout";
    private String clientId = "";
    private String clientSecret = "";
    private String redirectUri = "http://127.0.0.1:8088/";
    private String scope = "openid profile email";
    /** Required resource audience for direct OIDC bearer tokens; blank disables that path. */
    private String audience = "";
    /** Claim name used to scope admin API data per tenant. Blank falls back to the default tenant. */
    private String tenantClaim = "tenant_id";

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getJwkSetUri() {
        return jwkSetUri;
    }

    public void setJwkSetUri(String jwkSetUri) {
        this.jwkSetUri = jwkSetUri;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }

    public void setRegistrationEndpoint(String registrationEndpoint) {
        this.registrationEndpoint = registrationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public void setEndSessionEndpoint(String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getTenantClaim() {
        return tenantClaim;
    }

    public void setTenantClaim(String tenantClaim) {
        this.tenantClaim = tenantClaim;
    }
}
