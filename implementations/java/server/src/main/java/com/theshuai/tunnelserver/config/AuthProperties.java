package com.theshuai.tunnelserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Local username/password login for the management UI, as an alternative to OIDC. A successful
 * login mints a short-lived HS256 JWT that the admin API accepts alongside the gateway's RS256
 * tokens. Defaults to {@code admin/admin} for local development — change it before exposing.
 */
@Component
@ConfigurationProperties(prefix = "tunnel.auth")
public class AuthProperties {
    private boolean passwordLoginEnabled = true;
    /** Allow visitors to self-register USER-role accounts in the default tenant. */
    private boolean registrationEnabled = true;
    private String username = "admin";
    private String password = "admin";
    /** Default tenant used by local password-login and existing default-tenant data. */
    private String tenantId = "default";
    /** HS256 signing secret; when blank a random key is generated at startup (tokens reset on restart). */
    private String jwtSecret = "";
    private long tokenTtlSeconds = 28800;

    public boolean isPasswordLoginEnabled() {
        return passwordLoginEnabled;
    }

    public void setPasswordLoginEnabled(boolean passwordLoginEnabled) {
        this.passwordLoginEnabled = passwordLoginEnabled;
    }

    public boolean isRegistrationEnabled() {
        return registrationEnabled;
    }

    public void setRegistrationEnabled(boolean registrationEnabled) {
        this.registrationEnabled = registrationEnabled;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getJwtSecret() {
        return jwtSecret;
    }

    public void setJwtSecret(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public long getTokenTtlSeconds() {
        return tokenTtlSeconds;
    }

    public void setTokenTtlSeconds(long tokenTtlSeconds) {
        this.tokenTtlSeconds = tokenTtlSeconds;
    }
}
