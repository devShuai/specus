package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.ManagementUserService.LoginUser;
import com.theshuai.specusserver.management.service.RegistrationService;
import com.theshuai.specusserver.security.ClientAddressResolver;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.security.LoginRateLimiter;
import com.theshuai.specusserver.security.TurnstileVerifier;
import jakarta.servlet.http.HttpServletRequest;
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
    private final RegistrationService registrationService;
    private final TurnstileVerifier turnstileVerifier;
    private final LoginRateLimiter loginRateLimiter;
    private final ClientAddressResolver addressResolver;

    public AuthController(LocalTokenService localTokenService,
                          ManagementUserService managementUserService,
                          RegistrationService registrationService,
                          TurnstileVerifier turnstileVerifier,
                          LoginRateLimiter loginRateLimiter,
                          ClientAddressResolver addressResolver) {
        this.localTokenService = localTokenService;
        this.managementUserService = managementUserService;
        this.registrationService = registrationService;
        this.turnstileVerifier = turnstileVerifier;
        this.loginRateLimiter = loginRateLimiter;
        this.addressResolver = addressResolver;
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody(required = false) LoginRequest request,
                                   HttpServletRequest httpRequest) {
        if (request == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "用户名或密码错误"));
        }
        // 限流先于验证码与凭据校验:关闭 Turnstile 的部署同样受尝试次数约束。
        String loginIdentity = loginIdentity(request.tenantId(), request.username());
        loginRateLimiter.checkLoginAttempt(clientIp(httpRequest), loginIdentity);
        turnstileVerifier.verify(request.turnstileToken(), TurnstileVerifier.LOGIN_ACTION);
        return managementUserService.authenticate(request.username(), request.password(), request.tenantId())
                .<ResponseEntity<?>>map(user -> {
                    loginRateLimiter.recordSuccess(loginIdentity);
                    return ResponseEntity.ok(buildTokenBody(user));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "用户名或密码错误")));
    }

    /** 与其它安全敏感入口共用同一套可信代理边界,转发头只有来自可信代理时才被采纳。 */
    private String clientIp(HttpServletRequest request) {
        return addressResolver.resolve(request);
    }

    /**
     * 自助注册第一阶段：通过 Turnstile 后发送邮箱验证码，账号尚未创建。
     */
    @PostMapping("/auth/register")
    public ResponseEntity<?> register(@RequestBody(required = false) RegistrationRequest request) {
        if (!registrationService.isAvailable()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "当前未开放注册"));
        }
        if (request == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "请求体无效"));
        }
        turnstileVerifier.verify(request.turnstileToken(), TurnstileVerifier.REGISTER_ACTION);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(
                registrationService.requestRegistration(request.username(), request.email(), request.password()));
    }

    /** 自助注册第二阶段：校验邮件验证码，原子创建账号并签发登录 token。 */
    @PostMapping("/auth/register/verify")
    public ResponseEntity<?> verifyRegistration(@RequestBody(required = false) RegistrationVerificationRequest request) {
        if (request == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "请求体无效"));
        }
        LoginUser user = registrationService.verifyRegistration(request.registrationId(), request.code());
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
        return managementUserService.resolveLocalTokenUser(jwt.getSubject(), claimAsString(jwt, "tenant_id"))
                .<ResponseEntity<?>>map(user -> ResponseEntity.ok(buildTokenBody(user)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "账号已禁用、不存在或不再允许本地登录")));
    }

    private Map<String, Object> buildTokenBody(LoginUser user) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accessToken", localTokenService.issueToken(user.username(), user.tenantId(), user.role()));
        body.put("tokenType", "Bearer");
        body.put("expiresIn", localTokenService.getTtlSeconds());
        return body;
    }

    private static String loginIdentity(String tenantId, String username) {
        String tenant = tenantId == null ? "" : tenantId.trim().toLowerCase(java.util.Locale.ROOT);
        String user = username == null ? "" : username.trim().toLowerCase(java.util.Locale.ROOT);
        return tenant + '\u0000' + user;
    }

    public record LoginRequest(String username, String password, String turnstileToken, String tenantId) {
    }

    public record RegistrationRequest(String username, String email, String password, String turnstileToken) {
    }

    public record RegistrationVerificationRequest(String registrationId, String code) {
    }

    private static String claimAsString(Jwt jwt, String claimName) {
        Object value = jwt.getClaims().get(claimName);
        return value == null ? null : value.toString();
    }
}
