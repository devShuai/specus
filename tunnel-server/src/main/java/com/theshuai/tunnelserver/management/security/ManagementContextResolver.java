package com.theshuai.tunnelserver.management.security;

import com.theshuai.tunnelserver.config.AuthProperties;
import com.theshuai.tunnelserver.management.model.ManagementRole;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import com.theshuai.tunnelserver.management.tenant.TenantResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Component
public class ManagementContextResolver {
    public static final String ROLE_CLAIM = "role";

    private final AuthProperties authProperties;
    private final TenantResolver tenantResolver;

    public ManagementContextResolver(AuthProperties authProperties,
                                     TenantResolver tenantResolver) {
        this.authProperties = authProperties;
        this.tenantResolver = tenantResolver;
    }

    public ManagementContext resolve(Jwt jwt) {
        TenantContext tenant = tenantResolver.resolve(jwt);
        String username = jwt == null || jwt.getSubject() == null ? authProperties.getUsername() : jwt.getSubject();
        ManagementRole role = ManagementRole.parse(claimAsString(jwt, ROLE_CLAIM));
        boolean admin = username.equalsIgnoreCase(authProperties.getUsername()) || role == ManagementRole.ADMIN;
        return new ManagementContext(tenant, username, admin);
    }

    private static String claimAsString(Jwt jwt, String claimName) {
        if (jwt == null) {
            return null;
        }
        Object value = jwt.getClaims().get(claimName);
        return value == null ? null : value.toString();
    }
}
