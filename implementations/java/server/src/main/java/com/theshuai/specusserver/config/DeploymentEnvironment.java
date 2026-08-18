package com.theshuai.specusserver.config;

import org.springframework.util.StringUtils;

/**
 * Deployment environment that gates demo data and default-credential checks. Unset or unknown
 * values resolve to {@link #PROD} so a deployment never loses a production guard by typo.
 */
public enum DeploymentEnvironment {
    PROD,
    DEV,
    TEST;

    public static DeploymentEnvironment parse(String value) {
        if (!StringUtils.hasText(value)) {
            return PROD;
        }
        return switch (value.trim().toLowerCase()) {
            case "dev", "development", "local" -> DEV;
            case "test", "testing" -> TEST;
            default -> PROD;
        };
    }

    /** Demo accounts, demo credentials and other convenience data are only allowed outside prod. */
    public boolean allowsDemoData() {
        return this != PROD;
    }

    public boolean isProd() {
        return this == PROD;
    }
}
