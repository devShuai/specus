package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.config.AuthProperties;
import com.theshuai.tunnelserver.management.model.ManagementRole;
import com.theshuai.tunnelserver.management.service.ManagementUserService;
import com.theshuai.tunnelserver.management.service.ManagementUserService.LoginUser;
import com.theshuai.tunnelserver.management.tenant.TenantResolver;
import com.theshuai.tunnelserver.security.LocalTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Local username/password login. On success returns a short-lived Bearer JWT in the same shape as
 * the OIDC token exchange, so the SPA stores and uses it identically.
 */
@RestController
public class AuthController {
    private final LocalTokenService localTokenService;
    private final ManagementUserService managementUserService;
    private final AuthProperties authProperties;

    public AuthController(LocalTokenService localTokenService,
                          ManagementUserService managementUserService,
                          AuthProperties authProperties) {
        this.localTokenService = localTokenService;
        this.managementUserService = managementUserService;
        this.authProperties = authProperties;
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody(required = false) LoginRequest request) {
        if (request == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "用户名或密码错误"));
        }
        return managementUserService.authenticate(request.username(), request.password())
                .<ResponseEntity<?>>map(user -> ResponseEntity.ok(buildTokenBody(user)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "用户名或密码错误")));
    }

    /**
     * 自助注册：创建默认租户的 USER 账号并直接签发 token 完成登录。
     * 需要 {@code tunnel.auth.registration-enabled} 且密码登录开启。
     */
    @PostMapping("/auth/register")
    public ResponseEntity<?> register(@RequestBody(required = false) LoginRequest request) {
        if (!authProperties.isRegistrationEnabled() || !localTokenService.isPasswordLoginEnabled()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "当前未开放注册"));
        }
        if (request == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "请求体无效"));
        }
        LoginUser user = managementUserService.registerUser(request.username(), request.password());
        return ResponseEntity.ok(buildTokenBody(user));
    }

    /**
     * 仅本地 HS256 token（密码登录签发）可续期；OIDC 令牌返回 400 让前端走标准 OIDC 续期路径。
     * 该端点在 SecurityConfig 中需要鉴权，因此请求到这里时 jwt 已经被验证过。
     */
    @PostMapping("/auth/refresh")
    public ResponseEntity<?> refresh(@AuthenticationPrincipal Jwt jwt) {
        if (jwt == null || !LocalTokenService.ISSUER.equals(claimAsString(jwt, "iss"))) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "OIDC 令牌不能通过该端点续期"));
        }
        LoginUser user = new LoginUser(
                jwt.getSubject(),
                claimAsString(jwt, TenantResolver.LOCAL_TENANT_CLAIM),
                ManagementRole.parse(claimAsString(jwt, "role")),
                "ADMIN".equalsIgnoreCase(claimAsString(jwt, "role")));
        return ResponseEntity.ok(buildTokenBody(user));
    }

    private Map<String, Object> buildTokenBody(LoginUser user) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accessToken", localTokenService.issueToken(user.username(), user.tenantId(), user.role()));
        body.put("tokenType", "Bearer");
        body.put("expiresIn", localTokenService.getTtlSeconds());
        return body;
    }

    public record LoginRequest(String username, String password) {
    }

    private static String claimAsString(Jwt jwt, String claimName) {
        Object value = jwt.getClaims().get(claimName);
        return value == null ? null : value.toString();
    }
}
