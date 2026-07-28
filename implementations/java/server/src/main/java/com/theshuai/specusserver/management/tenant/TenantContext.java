package com.theshuai.specusserver.management.tenant;

import org.springframework.util.StringUtils;

/**
 * Tenant identity used to scope management data. Existing single-tenant deployments are mapped to
 * {@link #DEFAULT_TENANT_ID}; callers should normalize all external values before using them in
 * repository queries.
 */
public record TenantContext(String tenantId) {
    public static final String DEFAULT_TENANT_ID = "default";
    private static final int MAX_TENANT_ID_LENGTH = 80;

    public TenantContext {
        tenantId = normalize(tenantId);
    }

    public static TenantContext defaultTenant() {
        return new TenantContext(DEFAULT_TENANT_ID);
    }

    public static String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return DEFAULT_TENANT_ID;
        }
        String normalized = value.trim();
        if (normalized.length() > MAX_TENANT_ID_LENGTH) {
            throw new IllegalArgumentException("tenantId is too long");
        }
        return normalized;
    }
}
