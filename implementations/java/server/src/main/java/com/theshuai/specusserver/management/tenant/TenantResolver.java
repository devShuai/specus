package com.theshuai.specusserver.management.tenant;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.config.OidcProperties;
import com.theshuai.specusserver.security.LocalTokenService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Resolves the tenant from a verified management JWT. Local password-login tokens carry
 * {@code tenant_id}; OIDC tokens read the configured claim and fall back to the default tenant.
 */
@Component
public class TenantResolver {
    public static final String LOCAL_TENANT_CLAIM = "tenant_id";

    private final AuthProperties authProperties;
    private final OidcProperties oidcProperties;

    public TenantResolver(AuthProperties authProperties, OidcProperties oidcProperties) {
        this.authProperties = authProperties;
        this.oidcProperties = oidcProperties;
    }

    public TenantContext defaultTenant() {
        return new TenantContext(authProperties.getTenantId());
    }

    public TenantContext resolve(Jwt jwt) {
        if (jwt == null) {
            return defaultTenant();
        }
        String tenantId = null;
        if (LocalTokenService.ISSUER.equals(claimAsString(jwt, "iss"))) {
            tenantId = claimAsString(jwt, LOCAL_TENANT_CLAIM);
        } else if (StringUtils.hasText(oidcProperties.getTenantClaim())) {
            tenantId = claimAsString(jwt, oidcProperties.getTenantClaim());
        }
        return new TenantContext(StringUtils.hasText(tenantId) ? tenantId : authProperties.getTenantId());
    }

    private static String claimAsString(Jwt jwt, String claimName) {
        Object value = jwt.getClaims().get(claimName);
        return value == null ? null : value.toString();
    }
}
