package com.theshuai.specusserver.management.security;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.ManagementUserService.LoginUser;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.LocalTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

@Component
public class ManagementContextResolver {
    private final AuthProperties authProperties;
    private final ManagementUserService managementUserService;

    public ManagementContextResolver(AuthProperties authProperties,
                                     ManagementUserService managementUserService) {
        this.authProperties = authProperties;
        this.managementUserService = managementUserService;
    }

    public ManagementContext resolve(Jwt jwt) {
        if (jwt == null || jwt.getSubject() == null || jwt.getSubject().isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "缺少认证身份");
        }
        String issuer = claimAsString(jwt, "iss");
        Optional<LoginUser> resolved = LocalTokenService.ISSUER.equals(issuer)
                ? managementUserService.resolveLocalTokenUser(jwt.getSubject(), claimAsString(jwt, "tenant_id"))
                : managementUserService.resolveBoundOidcUser(issuer, jwt.getSubject());
        LoginUser user = resolved.orElseThrow(() -> new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "账号未绑定、已禁用或权限已撤销"));
        boolean builtIn = user.builtInAdmin()
                && user.username().equalsIgnoreCase(authProperties.getUsername());
        boolean admin = builtIn || user.role() == ManagementRole.ADMIN;
        return new ManagementContext(new TenantContext(user.tenantId()), user.username(), admin);
    }

    private static String claimAsString(Jwt jwt, String claimName) {
        if (jwt == null) {
            return null;
        }
        Object value = jwt.getClaims().get(claimName);
        return value == null ? null : value.toString();
    }
}
