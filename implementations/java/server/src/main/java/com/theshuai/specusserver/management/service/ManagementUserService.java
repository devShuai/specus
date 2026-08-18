package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.model.ManagementUserView;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
public class ManagementUserService {
    private final ManagementUserRepository repository;
    private final AuthProperties authProperties;

    public ManagementUserService(ManagementUserRepository repository,
                                 AuthProperties authProperties) {
        this.repository = repository;
        this.authProperties = authProperties;
    }

    @Transactional(readOnly = true)
    public Optional<LoginUser> authenticate(String username, String password) {
        return authenticate(username, password, null);
    }

    @Transactional(readOnly = true)
    public Optional<LoginUser> authenticate(String username, String password, String tenantId) {
        if (!StringUtils.hasText(username) || password == null) {
            return Optional.empty();
        }
        String normalized = normalizeUsername(username);
        String requestedTenant = null;
        if (StringUtils.hasText(tenantId)) {
            try {
                requestedTenant = TenantContext.normalize(tenantId);
            } catch (IllegalArgumentException invalidTenant) {
                return Optional.empty();
            }
        }
        String defaultTenant = TenantContext.normalize(authProperties.getTenantId());
        if (normalized.equalsIgnoreCase(authProperties.getUsername())
                && (requestedTenant == null || requestedTenant.equals(defaultTenant))) {
            if (!isAdminPasswordLoginEnabled()
                    || !constantTimeEquals(authProperties.getPassword(), password)) {
                return Optional.empty();
            }
            return Optional.of(new LoginUser(
                    authProperties.getUsername(),
                    defaultTenant,
                    ManagementRole.ADMIN,
                    true,
                    authProperties.getUsername()));
        }
        Optional<ManagementUser> candidate;
        if (requestedTenant != null) {
            candidate = repository.findByTenantIdAndLoginNameNormalized(requestedTenant, loginNameKey(normalized));
        } else {
            // Keep the default-tenant login flow unchanged for existing clients. Only fall back to
            // the legacy global account key when no default-tenant alias exists; non-default
            // tenants must be selected explicitly, so a tenant cannot probe another tenant here.
            candidate = repository.findByTenantIdAndLoginNameNormalized(
                            defaultTenant, loginNameKey(normalized))
                    .or(() -> uniqueLegacyAccountCandidate(normalized));
        }
        return candidate
                .filter(ManagementUser::isEnabled)
                .filter(user -> PasswordService.matches(password, user.getPasswordHash()))
                .map(this::toLoginUser);
    }

    /**
     * Resolves a verified Certus identity by its immutable issuer/subject pair. On first login an
     * enabled local user with the same imported username is linked; otherwise a least-privileged
     * USER is provisioned in the default tenant. Email and display-name claims are profile data and
     * never participate in account linking.
     */
    @Transactional
    public Optional<LoginUser> resolveOrProvisionOidcUser(
            String issuer,
            String subject,
            String preferredUsername) {
        if (!StringUtils.hasText(issuer)
                || !StringUtils.hasText(subject)
                || !StringUtils.hasText(preferredUsername)) {
            return Optional.empty();
        }
        String normalizedIssuer = issuer.trim();
        String normalizedSubject = subject.trim();
        if (normalizedIssuer.length() > 255 || normalizedSubject.length() > 255) {
            return Optional.empty();
        }
        String identityKey = oidcIdentityKey(normalizedIssuer, normalizedSubject);
        String normalized;
        try {
            normalized = normalizeUsername(preferredUsername);
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
        if (normalized.equalsIgnoreCase(authProperties.getUsername())) {
            // preferred_username is mutable profile data. It must never be sufficient to claim
            // the configured built-in administrator, which has no persistent OIDC binding row.
            return Optional.empty();
        }
        Optional<ManagementUser> bound = repository.findByOidcIdentityKey(identityKey);
        if (bound.isPresent()) {
            return bound.filter(ManagementUser::isEnabled).map(this::toLoginUser);
        }

        String tenantId = TenantContext.normalize(authProperties.getTenantId());
        Optional<ManagementUser> existing = repository.findByTenantIdAndLoginNameNormalized(
                tenantId, loginNameKey(normalized));
        if (existing.isPresent()) {
            ManagementUser user = existing.get();
            if (!user.isEnabled()) {
                return Optional.empty();
            }
            if (StringUtils.hasText(user.getOidcIssuer())
                    || StringUtils.hasText(user.getOidcSubject())) {
                return sameOidcIdentity(user, normalizedIssuer, normalizedSubject)
                        ? Optional.of(toLoginUser(user))
                        : Optional.empty();
            }
            repository.bindOidcIdentityIfUnbound(
                    user.getUsername(),
                    normalizedIssuer,
                    normalizedSubject,
                    identityKey,
                    Instant.now().toString());
            // Whether this request won the conditional update or another request got there first,
            // re-read the committed binding and accept only the exact immutable identity.
            return repository.findById(user.getUsername())
                    .filter(ManagementUser::isEnabled)
                    .filter(current -> sameOidcIdentity(current, normalizedIssuer, normalizedSubject))
                    .map(this::toLoginUser);
        }

        String now = Instant.now().toString();
        ManagementUser user = new ManagementUser();
        user.setUsername(newAccountKey());
        user.setLoginName(normalized);
        user.setLoginNameNormalized(loginNameKey(normalized));
        user.setTenantId(tenantId);
        user.setPasswordHash(PasswordService.hash(PasswordService.generatePassword()));
        user.setOidcIssuer(normalizedIssuer);
        user.setOidcSubject(normalizedSubject);
        user.setOidcIdentityKey(identityKey);
        user.setRole(ManagementRole.USER);
        user.setEnabled(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        return Optional.of(toLoginUser(repository.save(user)));
    }

    /** Resolves an already-bound external identity for direct OIDC bearer authentication. */
    @Transactional(readOnly = true)
    public Optional<LoginUser> resolveBoundOidcUser(String issuer, String subject) {
        if (!StringUtils.hasText(issuer) || !StringUtils.hasText(subject)) {
            return Optional.empty();
        }
        String normalizedIssuer = issuer.trim();
        String normalizedSubject = subject.trim();
        if (normalizedIssuer.length() > 255 || normalizedSubject.length() > 255) {
            return Optional.empty();
        }
        return repository.findByOidcIdentityKey(oidcIdentityKey(normalizedIssuer, normalizedSubject))
                .filter(ManagementUser::isEnabled)
                .filter(user -> sameOidcIdentity(user, normalizedIssuer, normalizedSubject))
                .map(this::toLoginUser);
    }

    /**
     * Re-resolves a locally minted token subject against current configuration/database state.
     * Refresh and request authorization use the current enabled flag, tenant and role rather than
     * copying stale claims from an older token.
     */
    @Transactional(readOnly = true)
    public Optional<LoginUser> resolveLocalTokenUser(String username) {
        return resolveLocalTokenUser(username, null);
    }

    @Transactional(readOnly = true)
    public Optional<LoginUser> resolveLocalTokenUser(String username, String tenantId) {
        if (!StringUtils.hasText(username)) {
            return Optional.empty();
        }
        String normalized;
        try {
            normalized = normalizeUsername(username);
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
        String requestedTenant = null;
        if (StringUtils.hasText(tenantId)) {
            try {
                requestedTenant = TenantContext.normalize(tenantId);
            } catch (IllegalArgumentException invalidTenant) {
                return Optional.empty();
            }
        }
        String defaultTenant = TenantContext.normalize(authProperties.getTenantId());
        if (normalized.equalsIgnoreCase(authProperties.getUsername())
                && (requestedTenant == null || requestedTenant.equals(defaultTenant))) {
            if (!isAdminPasswordLoginEnabled()) {
                return Optional.empty();
            }
            return Optional.of(new LoginUser(
                    authProperties.getUsername(),
                    defaultTenant,
                    ManagementRole.ADMIN,
                    true,
                    authProperties.getUsername()));
        }
        Optional<ManagementUser> candidate;
        if (requestedTenant != null) {
            candidate = repository.findByTenantIdAndLoginNameNormalized(requestedTenant, loginNameKey(normalized));
        } else {
            // Legacy local tokens store the immutable account key as sub, so this lookup is exact
            // and cannot become ambiguous when two tenants share a case-insensitive login name.
            candidate = repository.findById(normalized);
        }
        return candidate
                .filter(ManagementUser::isEnabled)
                .map(this::toLoginUser);
    }

    @Transactional(readOnly = true)
    public ManagementUserView currentUser(ManagementContext context) {
        if (context.username().equalsIgnoreCase(authProperties.getUsername())) {
            String now = Instant.now().toString();
            return new ManagementUserView(
                    authProperties.getUsername(),
                    context.tenant().tenantId(),
                    ManagementRole.ADMIN,
                    true,
                    true,
                    true,
                    now,
                    now);
        }
        return repository.findByTenantIdAndLoginNameNormalized(
                        context.tenant().tenantId(), loginNameKey(context.username()))
                .map(this::toView)
                .orElse(new ManagementUserView(
                        context.username(),
                        context.tenant().tenantId(),
                        context.isAdmin() ? ManagementRole.ADMIN : ManagementRole.USER,
                        context.isAdmin(),
                        false,
                        true,
                        null,
                        null));
    }

    @Transactional(readOnly = true)
    public List<ManagementUserView> listUsers(ManagementContext context) {
        requireAdmin(context);
        List<ManagementUserView> views = new ArrayList<>();
        String now = Instant.now().toString();
        views.add(new ManagementUserView(
                authProperties.getUsername(),
                context.tenant().tenantId(),
                ManagementRole.ADMIN,
                true,
                true,
                true,
                now,
                now));
        repository.findByTenantIdOrderByLoginNameAsc(context.tenant().tenantId()).stream()
                .map(this::toView)
                .forEach(views::add);
        return views.stream()
                .sorted(Comparator.comparing(ManagementUserView::builtIn).reversed()
                        .thenComparing(ManagementUserView::username, String.CASE_INSENSITIVE_ORDER))
                .toList();
    }

    LoginUser registerVerifiedUser(String rawUsername, String passwordHash) {
        String username = normalizeUsername(rawUsername);
        if (isReservedUsername(username)) {
            throw new IllegalArgumentException("该用户名不可用");
        }
        String tenantId = TenantContext.normalize(authProperties.getTenantId());
        if (repository.existsByTenantIdAndLoginNameNormalized(tenantId, loginNameKey(username))) {
            throw new IllegalArgumentException("用户名已存在: " + username);
        }
        if (!StringUtils.hasText(passwordHash) || !passwordHash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("密码摘要无效");
        }
        String now = Instant.now().toString();
        ManagementUser user = new ManagementUser();
        user.setUsername(newAccountKey());
        user.setLoginName(username);
        user.setLoginNameNormalized(loginNameKey(username));
        user.setTenantId(tenantId);
        user.setPasswordHash(passwordHash);
        user.setRole(ManagementRole.USER);
        user.setEnabled(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        ManagementUser saved = repository.saveAndFlush(user);
        return toLoginUser(saved);
    }

    boolean isReservedUsername(String username) {
        return StringUtils.hasText(username) && username.trim().equalsIgnoreCase(authProperties.getUsername());
    }

    @Transactional
    public ManagementUserView createUser(ManagementContext context, UserMutation request) {
        requireAdmin(context);
        String username = normalizeUsername(request.username());
        if (username.equalsIgnoreCase(authProperties.getUsername())) {
            throw new IllegalArgumentException("内置 admin 用户不能重复创建");
        }
        String tenantId = context.tenant().tenantId();
        String loginNameNormalized = loginNameKey(username);
        if (repository.existsByTenantIdAndLoginNameNormalized(tenantId, loginNameNormalized)) {
            auditCreateConflict(context, username);
            throw new IllegalArgumentException("用户名不可用");
        }
        String password = requirePassword(request.password());
        String now = Instant.now().toString();
        ManagementUser user = new ManagementUser();
        user.setUsername(newAccountKey());
        user.setLoginName(username);
        user.setLoginNameNormalized(loginNameNormalized);
        user.setTenantId(tenantId);
        user.setPasswordHash(PasswordService.hash(password));
        user.setRole(request.role() == null ? ManagementRole.USER : request.role());
        user.setEnabled(request.enabled() == null || request.enabled());
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        try {
            return toView(repository.saveAndFlush(user));
        } catch (DataIntegrityViolationException conflict) {
            auditCreateConflict(context, username);
            throw new IllegalArgumentException("用户名不可用", conflict);
        }
    }

    @Transactional
    public ManagementUserView updateUser(ManagementContext context, String username, UserMutation request) {
        requireAdmin(context);
        String normalized = normalizeUsername(username);
        if (normalized.equalsIgnoreCase(authProperties.getUsername())) {
            throw new IllegalArgumentException("内置 admin 用户只能通过配置文件修改");
        }
        ManagementUser user = requireMutableUserInTenant(context, normalized, "update");
        if (StringUtils.hasText(request.password())) {
            user.setPasswordHash(PasswordService.hash(request.password().trim()));
        }
        if (request.role() != null) {
            user.setRole(request.role());
        }
        if (request.enabled() != null) {
            user.setEnabled(request.enabled());
        }
        user.setUpdatedAt(Instant.now().toString());
        return toView(repository.save(user));
    }

    @Transactional
    public void deleteUser(ManagementContext context, String username) {
        requireAdmin(context);
        String normalized = normalizeUsername(username);
        if (normalized.equalsIgnoreCase(authProperties.getUsername())) {
            throw new IllegalArgumentException("内置 admin 用户不能删除");
        }
        repository.delete(requireMutableUserInTenant(context, normalized, "delete"));
    }

    /**
     * Mutation targets must belong to the acting administrator's tenant. Missing users and users
     * that only exist in another tenant are indistinguishable to the caller so a tenant-A admin
     * cannot probe tenant-B usernames; the rejected attempt is still recorded for auditing.
     */
    private ManagementUser requireMutableUserInTenant(ManagementContext context, String normalized, String action) {
        return repository.findByTenantIdAndLoginNameNormalized(
                        context.tenant().tenantId(), loginNameKey(normalized))
                .orElseThrow(() -> {
                    log.warn("管理用户{}被拒绝: actor={}, tenant={}, target={}, reason=目标不在当前租户或不存在",
                            action, context.username(), context.tenant().tenantId(), normalized);
                    return new IllegalArgumentException("用户不存在: " + normalized);
                });
    }

    private void auditCreateConflict(ManagementContext context, String loginName) {
        log.warn("管理用户create被拒绝: actor={}, tenant={}, target={}, reason=当前租户登录名冲突",
                context.username(), context.tenant().tenantId(), loginName);
    }

    public void requireAdmin(ManagementContext context) {
        if (context == null || !context.isAdmin()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "需要 admin 权限");
        }
    }

    private boolean isAdminPasswordLoginEnabled() {
        return authProperties.isPasswordLoginEnabled() && StringUtils.hasText(authProperties.getPassword());
    }

    private ManagementUserView toView(ManagementUser user) {
        boolean admin = user.getRole() == ManagementRole.ADMIN;
        return new ManagementUserView(
                loginName(user),
                TenantContext.normalize(user.getTenantId()),
                user.getRole(),
                admin,
                false,
                user.isEnabled(),
                user.getCreatedAt(),
                user.getUpdatedAt());
    }

    private LoginUser toLoginUser(ManagementUser user) {
        return new LoginUser(loginName(user), user.getTenantId(), user.getRole(), false, user.getUsername());
    }

    private Optional<ManagementUser> uniqueLegacyAccountCandidate(String username) {
        List<ManagementUser> matches = repository.findAllByUsernameIgnoreCase(username);
        return matches.size() == 1 ? Optional.of(matches.getFirst()) : Optional.empty();
    }

    private String loginName(ManagementUser user) {
        return StringUtils.hasText(user.getLoginName()) ? user.getLoginName() : user.getUsername();
    }

    String loginNameKey(String loginName) {
        return loginName.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private String newAccountKey() {
        return UUID.randomUUID().toString();
    }

    private boolean sameOidcIdentity(ManagementUser user, String issuer, String subject) {
        return oidcIdentityKey(issuer, subject).equals(user.getOidcIdentityKey());
    }

    private String oidcIdentityKey(String issuer, String subject) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(issuer.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(subject.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    String normalizeUsername(String username) {
        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException("username cannot be blank");
        }
        String normalized = username.trim();
        if (normalized.length() > 80) {
            throw new IllegalArgumentException("username is too long");
        }
        return normalized;
    }

    String requirePassword(String password) {
        if (!StringUtils.hasText(password)) {
            throw new IllegalArgumentException("password cannot be blank");
        }
        String normalized = password.trim();
        if (normalized.length() > 120) {
            throw new IllegalArgumentException("password is too long");
        }
        return normalized;
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                actual.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public record LoginUser(
            String username,
            String tenantId,
            ManagementRole role,
            boolean builtInAdmin,
            String accountKey) {
        public LoginUser(String username, String tenantId, ManagementRole role, boolean builtInAdmin) {
            this(username, tenantId, role, builtInAdmin, username);
        }
    }

    public record UserMutation(String username, String password, ManagementRole role, Boolean enabled) {
    }
}
