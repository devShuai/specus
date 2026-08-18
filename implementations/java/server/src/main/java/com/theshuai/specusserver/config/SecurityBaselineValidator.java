package com.theshuai.specusserver.config;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Locale;
import java.util.Set;

/**
 * Fails startup when a production deployment still carries credentials that ship with the project
 * or are trivially guessable. Non-production environments only log a warning so local runs and
 * tests keep working.
 */
@Slf4j
@Component
public class SecurityBaselineValidator {
    /** Values published in the repository, docs and demo data, plus the usual throwaway passwords. */
    private static final Set<String> KNOWN_DEFAULT_PASSWORDS = Set.of(
            "admin", "password", "123456", "12345678", "changeme", "change-me",
            "change_me_admin_password", "change-me-before-exposure",
            "specus", "test1234", "demo");
    private static final Set<String> KNOWN_DEFAULT_JWT_SECRETS = Set.of(
            "replace-with-a-long-random-secret");

    private final AuthProperties authProperties;
    private final DeploymentEnvironment environment;
    private final boolean seedDemoClientRequested;

    public SecurityBaselineValidator(AuthProperties authProperties,
                                     @Value("${specus.env:}") String environmentName,
                                     @Value("${specus.database.seed-demo-client:true}") boolean seedDemoClientRequested) {
        this.authProperties = authProperties;
        this.environment = DeploymentEnvironment.parse(environmentName);
        this.seedDemoClientRequested = seedDemoClientRequested;
    }

    public DeploymentEnvironment environment() {
        return environment;
    }

    @PostConstruct
    public void validate() {
        String password = authProperties.getPassword();
        boolean passwordLoginConfigured = authProperties.isPasswordLoginEnabled() && StringUtils.hasText(password);

        if (passwordLoginConfigured && isKnownDefaultPassword(password)) {
            String message = "specus.auth.password 使用了已知默认口令，禁止在 " + environment
                    + " 环境启动；请设置 SPECUS_AUTH_PASSWORD 或置空以关闭密码登录";
            if (environment.isProd()) {
                throw new IllegalStateException(message);
            }
            log.warn("[security-baseline] {}", message);
        }

        if (isKnownDefaultJwtSecret(authProperties.getJwtSecret())) {
            String message = "specus.auth.jwt-secret 使用了公开占位值，禁止在 " + environment
                    + " 环境启动；请设置随机 SPECUS_AUTH_JWT_SECRET 或置空以使用临时密钥";
            if (environment.isProd()) {
                throw new IllegalStateException(message);
            }
            log.warn("[security-baseline] {}", message);
        }

        if (environment.isProd() && seedDemoClientRequested) {
            log.warn("[security-baseline] prod 环境忽略 specus.database.seed-demo-client=true，不会创建演示客户端与演示凭据");
        }

        if (environment.isProd() && !passwordLoginConfigured) {
            log.info("[security-baseline] 密码登录未启用；请通过 OIDC 或显式配置 SPECUS_AUTH_PASSWORD 访问管理端");
        }
    }

    private boolean isKnownDefaultPassword(String password) {
        return KNOWN_DEFAULT_PASSWORDS.contains(password.trim().toLowerCase(Locale.ROOT));
    }

    private boolean isKnownDefaultJwtSecret(String secret) {
        return StringUtils.hasText(secret)
                && KNOWN_DEFAULT_JWT_SECRETS.contains(secret.trim().toLowerCase(Locale.ROOT));
    }
}
