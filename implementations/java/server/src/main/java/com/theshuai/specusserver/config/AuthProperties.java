package com.theshuai.specusserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Local username/password login for the management UI, as an alternative to OIDC. A successful
 * login mints a short-lived HS256 JWT that the admin API accepts alongside the gateway's RS256
 * tokens. The password is empty by default, which disables this login until an operator sets one;
 * see {@link SecurityBaselineValidator} for the production checks applied to configured values.
 */
@Component
@ConfigurationProperties(prefix = "specus.auth")
public class AuthProperties {
    private boolean passwordLoginEnabled = true;
    /** Allow visitors to self-register USER-role accounts in the default tenant. */
    private boolean registrationEnabled = true;
    private String username = "admin";
    private String password = "";
    private final LoginRateLimit loginRateLimit = new LoginRateLimit();
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

    public LoginRateLimit getLoginRateLimit() {
        return loginRateLimit;
    }

    /**
     * Application-level login throttling. It applies independently of the captcha so deployments
     * that run without Turnstile still bound credential stuffing.
     */
    public static class LoginRateLimit {
        private boolean enabled = true;
        private int perIp = 20;
        private int perAccount = 10;
        private long windowSeconds = 300;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getPerIp() {
            return perIp;
        }

        public void setPerIp(int perIp) {
            this.perIp = perIp;
        }

        public int getPerAccount() {
            return perAccount;
        }

        public void setPerAccount(int perAccount) {
            this.perAccount = perAccount;
        }

        public long getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(long windowSeconds) {
            this.windowSeconds = windowSeconds;
        }
    }
}
